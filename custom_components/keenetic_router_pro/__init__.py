"""Keenetic Router Pro integration root."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
import re
from typing import Any

import voluptuous as vol
from aiohttp import ClientError, ClientSession, DummyCookieJar
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_CLOSE
from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
    callback,
)
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    ConfigEntryError,
    ConfigEntryNotReady,
    HomeAssistantError,
    ServiceValidationError,
)
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .api import (
    KeeneticClient,
    KeeneticApiError,
    KeeneticCredentialsError,
    KeeneticUnsupportedAuthError,
    describe_error,
)
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
_DATA_HTTP_SESSION = f"{DOMAIN}_http_session"


@callback
def async_get_router_session(hass: HomeAssistant) -> ClientSession:
    """Share a connection pool without sharing router authentication cookies."""
    if (session := hass.data.get(_DATA_HTTP_SESSION)) is None:
        # KeeneticClient explicitly sends the cookie from its own handshake.
        # An automatic jar would replay it during another client's GET /auth.
        session = async_create_clientsession(
            hass, auto_cleanup=False, cookie_jar=DummyCookieJar()
        )
        hass.data[_DATA_HTTP_SESSION] = session

        @callback
        def detach_session(_event: Any) -> None:
            hass.data.pop(_DATA_HTTP_SESSION)
            session.detach()

        # CLOSE, not STOP: entries are still unloading (and may make a
        # last request) during STOP; Home Assistant's own shared sessions
        # are detached on CLOSE too.
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_CLOSE, detach_session)

    return session


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


_CLIENT_DEVICE_PREFIX = "client_"
_MAC_RE = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")


def _tracked_macs(entry: ConfigEntry) -> set[str]:
    """MACs of the clients the user currently tracks (lower case)."""
    return {
        str(client.get("mac") or "").lower()
        for client in entry.data.get(CONF_TRACKED_CLIENTS, []) or []
        if isinstance(client, dict) and client.get("mac")
    }


def _client_device_mac(device: Any) -> str | None:
    """The MAC behind a tracked-client device, or None for other devices.

    Client devices are identified by ``(DOMAIN, "client_aa_bb_cc_dd_ee_ff")``
    (see ``utils.get_client_device_info``); router, mesh, WAN and crypto
    map devices use other identifiers and are never matched here.
    """
    for domain, identifier in getattr(device, "identifiers", set()) or set():
        if domain == DOMAIN and identifier.startswith(_CLIENT_DEVICE_PREFIX):
            mac = identifier[len(_CLIENT_DEVICE_PREFIX):].replace("_", ":").lower()
            if _MAC_RE.fullmatch(mac):
                return mac
    return None


@callback
def _async_remove_untracked_clients(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Delete the devices and entities of clients no longer tracked.

    Removing a client in the options flow only changes the tracked list;
    without this its device (tracker, sensors, buttons, ...) stayed behind
    as "unavailable" forever. Runs on every setup, so the options-flow
    reload cleans up straight away, and leftovers from older releases are
    removed on the first start. Only this entry's own client devices are
    touched.
    """
    tracked = _tracked_macs(entry)
    dev_reg = dr.async_get(hass)
    removed_devices = 0
    for device in list(dr.async_entries_for_config_entry(dev_reg, entry.entry_id)):
        mac = _client_device_mac(device)
        if mac is not None and mac not in tracked:
            if hasattr(device, "config_entry_id"):
                # HA 2026.8+: a device has exactly one config entry; HA
                # also removes the entities this entry has on it.
                dev_reg.async_remove_device(device.id)
            else:
                # Older cores: the device may be shared with another
                # router entry or another integration (same MAC). Take
                # only this entry off it; HA deletes the device once no
                # entry is left and removes only this entry's entities.
                dev_reg.async_update_device(
                    device.id, remove_config_entry_id=entry.entry_id
                )
            removed_devices += 1

    # Per-client entities that lost their device earlier would survive the
    # pass above; their unique_id is "<entry_id>_client_<mac>[_suffix]".
    ent_reg = er.async_get(hass)
    prefix = f"{entry.entry_id}_{_CLIENT_DEVICE_PREFIX}"
    removed_entities = 0
    for ent in list(er.async_entries_for_config_entry(ent_reg, entry.entry_id)):
        unique_id = str(ent.unique_id or "")
        if not unique_id.startswith(prefix):
            continue
        mac = unique_id[len(prefix):len(prefix) + 17].lower()
        if _MAC_RE.fullmatch(mac) and mac not in tracked:
            ent_reg.async_remove(ent.entity_id)
            removed_entities += 1

    if removed_devices or removed_entities:
        _LOGGER.info(
            "Removed %d device(s) and %d other entit(y/ies) of clients that are "
            "no longer tracked",
            removed_devices,
            removed_entities,
        )


async def async_remove_config_entry_device(
    hass: HomeAssistant, config_entry: ConfigEntry, device_entry: Any
) -> bool:
    """Let the user delete a client device that is no longer tracked.

    A tracked client's device would come back on the next reload, and the
    router / mesh / WAN devices belong to the integration itself, so those
    are refused; remove the client from the tracked list instead.
    """
    mac = _client_device_mac(device_entry)
    return mac is not None and mac not in _tracked_macs(config_entry)


SERVICE_LIST_PORT_FORWARDS = "list_port_forwards"
ATTR_CONFIG_ENTRY_ID = "config_entry_id"


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Register the integration's actions (once, for all routers)."""

    async def async_list_port_forwards(call: ServiceCall) -> ServiceResponse:
        """Read the port forwarding rules straight from the router."""
        entry_id = call.data[ATTR_CONFIG_ENTRY_ID]
        entry_data = hass.data.get(DOMAIN, {}).get(entry_id)
        if not isinstance(entry_data, dict) or DATA_CLIENT not in entry_data:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="entry_not_loaded",
            )
        client: KeeneticClient = entry_data[DATA_CLIENT]
        try:
            rules = await client.async_get_port_forwards(fresh=True)
        except (KeeneticApiError, TimeoutError, ClientError, ValueError) as err:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="port_forward_read_failed",
                translation_placeholders={"error": describe_error(err)},
            ) from err
        return {
            "rules": sorted(
                rules.values(),
                key=lambda r: (r["interface"], str(r["protocol"]), str(r["port"])),
            )
        }

    hass.services.async_register(
        DOMAIN,
        SERVICE_LIST_PORT_FORWARDS,
        async_list_port_forwards,
        schema=vol.Schema(
            {vol.Required(ATTR_CONFIG_ENTRY_ID): vol.All(str, vol.Length(min=1))}
        ),
        supports_response=SupportsResponse.ONLY,
    )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data: dict[str, Any] = dict(entry.data)

    # Before talking to the router: needs only the entry and the registries,
    # so it also runs when the router is unreachable.
    _async_remove_untracked_clients(hass, entry)

    host: str = data.get("host") or data.get("ip") 
    username: str = data["username"]
    password: str = data["password"]
    port: int = int(data.get("port", DEFAULT_PORT))
    use_ssl: bool = bool(data.get("ssl", DEFAULT_SSL))

    session = async_get_router_session(hass)

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
    except KeeneticUnsupportedAuthError as err:
        # Must come before KeeneticAuthError (it is a subclass). A
        # reauth flow can never succeed here — the password is likely
        # right, the router wants a sign-in we couldn't complete — and
        # every retry adds a failed login towards the router's
        # brute-force ban. ConfigEntryError stops HA from retrying and
        # shows this message on the integration card instead.
        raise ConfigEntryError(
            "The router requires the KeeneticOS 5.2 sign-in method (NDW4) "
            f"and it could not be completed: {err}. See GitHub issue #71."
        ) from err
    except KeeneticCredentialsError as err:
        # The router definitely refused the user name or password ->
        # ConfigEntryAuthFailed, which HA wires into the reauth flow
        # (Repairs card + notification + async_step_reauth).
        raise ConfigEntryAuthFailed(
            "Keenetic credentials were rejected"
        ) from err
    except KeeneticApiError as err:
        # Includes the other KeeneticAuthError cases (an unexpected /auth
        # status while the router boots, a cloud proxy answering 502/503,
        # no challenge header): not a password verdict, so retry with
        # backoff instead of asking the user to re-enter a correct password.
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

    # Issue #64: async_start may have fallen back from Basic to the
    # challenge handshake. The config flow persists that for new and
    # reconfigured entries, but an entry created before this fix would
    # otherwise repeat the doomed Basic 401 round-trip on every restart.
    # Writing it here is safe: the update listener that reloads the entry
    # on change is only registered at the very end of setup, so this
    # cannot re-enter.
    if client.use_challenge_auth != bool(
        entry.data.get(CONF_USE_CHALLENGE_AUTH, False)
    ):
        _LOGGER.info(
            "Persisting challenge auth on the config entry — the router "
            "refused Basic auth"
        )
        hass.config_entries.async_update_entry(
            entry,
            data={
                **entry.data,
                CONF_USE_CHALLENGE_AUTH: client.use_challenge_auth,
            },
        )

    # Issue #69: DeviceInfo["via_device"] is deprecated (removed in HA
    # 2027.8.0) in favour of DeviceInfo["via_device_id"], which needs a
    # real device registry id rather than an identifier tuple. Create the
    # router device here — before platforms are forwarded — so every
    # sub-device (mesh node, WAN, crypto map, tracked client) can link to
    # it no matter which platform HA sets up first. ControllerEntity
    # enriches this same identifier with model / firmware /
    # configuration_url moments later.
    device_reg = dr.async_get(hass)
    main_device = device_reg.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, entry.entry_id)},
        manufacturer="Keenetic",
        name=entry.title,
    )
    coordinator.main_device_id = main_device.id

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
