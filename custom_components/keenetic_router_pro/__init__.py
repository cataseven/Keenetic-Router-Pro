"""Keenetic Router Pro integration root."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import KeeneticClient, KeeneticAuthError, KeeneticApiError
from .const import (
    DOMAIN,
    DEFAULT_PORT,
    DEFAULT_SSL,
    DATA_CLIENT,
    DATA_COORDINATOR,
    DATA_PING_COORDINATOR,
    CONF_TRACKED_CLIENTS,
    CONF_USE_CHALLENGE_AUTH,
    CONF_PING_INTERVAL,
    DEFAULT_PING_INTERVAL,
    EVENT_NEW_DEVICE,
    CLOUD_STARTUP_JITTER_PER_ENTRY,
    CLOUD_STARTUP_JITTER_CAP,
)
from .coordinator import KeeneticCoordinator, KeeneticPingCoordinator

_LOGGER = logging.getLogger(__name__)

# HA Repairs panel issue ID prefix. The entry_id is appended so each
# misconfigured entry produces its own card, and the card disappears
# the moment that entry is reconfigured to use HTTPS.
ISSUE_INSECURE_HTTP = "insecure_http"


def _is_loopback_host(host: str) -> bool:
    """Return True when ``host`` is a loopback address / hostname.

    Plaintext HTTP to a loopback target (HA on the same box as the
    router, or a SSH tunnel terminating on 127.0.0.1) doesn't expose
    credentials to anyone on the LAN — those packets never leave the
    machine. Skip the warning for those cases so the Repairs card
    only fires on the genuinely insecure setups.
    """
    candidate = (host or "").strip().lower()
    if candidate in {"localhost", "ip6-localhost", "ip6-loopback"}:
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        # Hostname that isn't a literal IP address — treat as remote.
        return False


@callback
def _async_update_insecure_http_issue(
    hass: HomeAssistant,
    entry: ConfigEntry,
    host: str,
    use_ssl: bool,
) -> None:
    """Raise / clear the plaintext-HTTP Repair card for one config entry.

    When SSL is disabled and the router is not on loopback, every
    coordinator poll sends the Basic Auth header (or the NDW2
    challenge response + session cookie) across the LAN in plaintext.
    Anyone on the same broadcast domain can capture it. The Repair
    card surfaces that explicitly with a learn-more link to SECURITY.md
    so the operator knows what's at stake and how to fix it.

    Called on every setup_entry — if the user reconfigures to HTTPS
    the same call deletes the issue, so no manual dismissal needed.
    """
    issue_id = f"{ISSUE_INSECURE_HTTP}_{entry.entry_id}"
    if not use_ssl and not _is_loopback_host(host):
        ir.async_create_issue(
            hass,
            DOMAIN,
            issue_id,
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key=ISSUE_INSECURE_HTTP,
            translation_placeholders={"host": host, "title": entry.title},
            learn_more_url=(
                "https://github.com/cataseven/Keenetic-Router-Pro/"
                "blob/main/SECURITY.md"
            ),
        )
    else:
        ir.async_delete_issue(hass, DOMAIN, issue_id)


PLATFORMS: list[str] = ["sensor", "switch", "device_tracker", "button", "binary_sensor", "select", "update", "image", "number"]


def _is_cloud_host_entry(entry: ConfigEntry) -> bool:
    """Cheap cloud-mode test for a config entry (no client construction)."""
    from .api import is_cloud_keendns_host

    return is_cloud_keendns_host(
        entry.data.get("host") or entry.data.get("ip") or "",
        bool(entry.data.get("ssl", DEFAULT_SSL)),
    )


def _cloud_startup_jitter(hass: HomeAssistant, entry: ConfigEntry) -> float:
    """Seconds to wait before this cloud entry's first poll.

    Issue #43 root cause: on HA restart every configured router fires
    its first coordinator refresh at virtually the same instant. For
    cloud-KeenDNS routers that means one synchronised spike of 25-40
    RCI calls *per router* arriving at Keenetic's proxy from a single
    WAN IP — read as a brute-force flood, so the proxy drops the auth
    cookie on every cloud site at once.

    We de-correlate those first polls with a randomised delay scaled by
    how many *other* cloud entries exist. A lone cloud router waits ~0 s
    (its own per-request pacing already smooths its single burst); a
    fleet spreads first polls across a window that grows with the fleet
    size, capped so startup never stalls unreasonably. Direct-LAN
    entries always return 0.0.
    """
    try:
        if not _is_cloud_host_entry(entry):
            return 0.0
    except Exception:  # noqa: BLE001 — never block setup on detection
        return 0.0

    # Count *other* cloud entries (this one is already in the registry).
    sibling_cloud = 0
    for other in hass.config_entries.async_entries(DOMAIN):
        if other.entry_id == entry.entry_id:
            continue
        try:
            if _is_cloud_host_entry(other):
                sibling_cloud += 1
        except Exception:  # noqa: BLE001
            continue

    window = min(
        CLOUD_STARTUP_JITTER_PER_ENTRY * sibling_cloud,
        CLOUD_STARTUP_JITTER_CAP,
    )
    return random.uniform(0.0, window) if window > 0 else 0.0


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data: dict[str, Any] = dict(entry.data)

    host: str = data.get("host") or data.get("ip") 
    username: str = data["username"]
    password: str = data["password"]
    port: int = int(data.get("port", DEFAULT_PORT))
    use_ssl: bool = bool(data.get("ssl", DEFAULT_SSL))

    session = async_get_clientsession(hass)

    client = KeeneticClient(
        host=host,
        username=username,
        password=password,
        port=port,
        ssl=use_ssl,
        use_challenge_auth=bool(data.get(CONF_USE_CHALLENGE_AUTH, False)),
    )
    try:
        await client.async_start(session)
    except KeeneticAuthError as err:
        # Auth-specific failure -> raise ConfigEntryAuthFailed which
        # HA wires automatically into the reauth flow (Repairs card
        # + notification + the async_step_reauth handler in
        # config_flow.py). Without this exception type the user would
        # see a generic "integration failed to set up" with no path
        # to fix the credentials.
        raise ConfigEntryAuthFailed(
            "Keenetic credentials were rejected"
        ) from err
    except KeeneticApiError as err:
        # Connection / transport error (router unreachable, 5xx,
        # timeout) -> ConfigEntryNotReady triggers HA's retry-with-
        # backoff. Same surface as before, just typed correctly so
        # HA's startup logs read as "will retry" instead of "failed".
        raise ConfigEntryNotReady(
            f"Could not connect to Keenetic router: {err}"
        ) from err

    coordinator = KeeneticCoordinator(hass, client)

    # Issue #43: spread cloud routers' first polls so a HA restart
    # doesn't fire every router's 25-40-call burst at the proxy
    # simultaneously. No-op (0 s) for direct-LAN entries and for a
    # lone cloud router.
    jitter = _cloud_startup_jitter(hass, entry)
    if jitter > 0:
        _LOGGER.debug(
            "Delaying first poll of %s by %.1fs to de-correlate cloud "
            "router startup (issue #43)",
            entry.title,
            jitter,
        )
        await asyncio.sleep(jitter)

    await coordinator.async_config_entry_first_refresh()

    # Plaintext-HTTP Repair card intentionally disabled per user
    # preference. The security warning is real (LAN sniff vector) but
    # the practical risk on a trusted home LAN is low, and the card
    # was noise rather than signal for this deployment. We still call
    # ``async_delete_issue`` unconditionally so any card left over
    # from a prior version of this integration is cleaned up on the
    # first setup after the change — without this, an existing card
    # would linger until the user manually dismissed or reloaded the
    # integration.
    #
    # The helper ``_async_update_insecure_http_issue`` is intentionally
    # left in place above; flip the call back on if the threat model
    # changes (e.g. moving to a hotel / shared-LAN deployment).
    ir.async_delete_issue(
        hass, DOMAIN, f"{ISSUE_INSECURE_HTTP}_{entry.entry_id}"
    )

    tracked_clients = data.get(CONF_TRACKED_CLIENTS, [])

    # Ping interval: options flow takes precedence over data, falls back to default.
    ping_interval = entry.options.get(
        CONF_PING_INTERVAL,
        data.get(CONF_PING_INTERVAL, DEFAULT_PING_INTERVAL),
    )
    try:
        ping_interval = int(ping_interval)
    except (TypeError, ValueError):
        ping_interval = DEFAULT_PING_INTERVAL
    if ping_interval < 1:
        ping_interval = DEFAULT_PING_INTERVAL

    ping_coordinator = KeeneticPingCoordinator(
        hass, client, tracked_clients, interval=ping_interval
    )

    if tracked_clients:
        # async_config_entry_first_refresh yerine async_refresh kullanıyoruz.
        # Ping sırasında CancelledError veya başka bir hata olursa setup
        # iptal edilmesin; coordinator boş veriyle başlasın, sonraki
        # döngüde tekrar denensin.
        try:
            await ping_coordinator.async_refresh()
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning(
                "Initial ping refresh failed (non-fatal), will retry on next cycle: %s", err
            )

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        DATA_CLIENT: client,
        DATA_COORDINATOR: coordinator,
        DATA_PING_COORDINATOR: ping_coordinator,
    }

    @callback
    def _async_handle_new_device() -> None:
        """Yeni cihaz bağlandığında event tetikle."""
        new_clients = coordinator.data.get("new_clients", set())
        clients = coordinator.data.get("clients", [])
        
        for mac in new_clients:
            client_info = None
            for c in clients:
                if str(c.get("mac") or "").lower() == mac:
                    client_info = c
                    break
            
            if client_info:
                name = client_info.get("name") or client_info.get("hostname") or mac.upper()
                ip = client_info.get("ip")
                
                _LOGGER.info("New device connected: %s (%s) - %s", name, mac, ip)
                
                hass.bus.async_fire(
                    EVENT_NEW_DEVICE,
                    {
                        "mac": mac,
                        "name": name,
                        "ip": ip,
                        "hostname": client_info.get("hostname"),
                        "interface": client_info.get("interface"),
                        "ssid": client_info.get("ssid"),
                    },
                )

    coordinator.async_add_listener(_async_handle_new_device)

    # One-shot migration for v1.12.0 → v1.12.x upgraders.
    #
    # v1.12.0 shipped the new ``KeeneticMeshPortSpeedSensor`` with
    # ``_attr_entity_registry_enabled_default = False``, intending to
    # keep the entity registry tidy on multi-port mesh extenders.
    # That decision broke the symmetry with the controller-side
    # port-speed sensor (which was enabled by default) and confused
    # users who expected one speed entity per port across all devices.
    # v1.12.1 flipped the default back to enabled, but Home Assistant
    # only honours ``enabled_default`` when an entity is *first*
    # registered — entities already in the registry keep their
    # "disabled-by-integration" flag and stay invisible on the
    # dashboard until manually re-enabled. That's a registry-level
    # quirk we have to repair in code; users won't (and shouldn't
    # have to) walk through 4-12 disabled entities clicking Enable.
    #
    # We only flip entities that we ourselves disabled
    # (``RegistryEntryDisabler.INTEGRATION``) — never user choices.
    # Pattern is the port-speed unique_id shape used by both the
    # controller and mesh classes: ends with ``_speed`` and contains
    # ``_port_``. Future port-speed-shaped entities added by the
    # integration will also benefit if anyone ever ships them with
    # the wrong default again; the cost is negligible since the loop
    # runs once at setup and only touches matching entries.
    try:
        ent_reg = er.async_get(hass)
        for ent in list(ent_reg.entities.values()):
            if ent.config_entry_id != entry.entry_id:
                continue
            if ent.disabled_by != er.RegistryEntryDisabler.INTEGRATION:
                continue
            uid = ent.unique_id or ""
            if not uid.endswith("_speed") or "_port_" not in uid:
                continue
            ent_reg.async_update_entity(ent.entity_id, disabled_by=None)
            _LOGGER.info(
                "Re-enabled %s (was disabled by v1.12.0's wrong default)",
                ent.entity_id,
            )
    except Exception:  # noqa: BLE001
        # Migration is best-effort. If HA changes its registry API
        # shape on us, swallowing here keeps setup itself working;
        # affected users can still re-enable manually.
        _LOGGER.exception(
            "Port-speed entity re-enable migration failed — entities "
            "may need manual enabling in Settings → Entities"
        )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    entry.async_on_unload(entry.add_update_listener(async_update_listener))
    
    return True


async def async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Config entry güncellendiğinde çağrılır (options flow sonrası)."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Config entry silinir veya devre dışı bırakılırken çalışır."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unload_ok:
        return False

    entry_data = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if entry_data:
        client: KeeneticClient = entry_data.get(DATA_CLIENT)

    if not hass.data.get(DOMAIN):
        hass.data.pop(DOMAIN, None)

    # Remove the plaintext-HTTP Repair card if this entry raised one.
    # Otherwise the card lingers in the Repairs panel pointing at a
    # config entry that no longer exists.
    ir.async_delete_issue(
        hass, DOMAIN, f"{ISSUE_INSECURE_HTTP}_{entry.entry_id}"
    )

    return True
