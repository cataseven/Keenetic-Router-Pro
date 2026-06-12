"""Device tracker (presence) for Keenetic Router Pro."""
from __future__ import annotations
from typing import Any
# ScannerEntity must come from the package root: the
# homeassistant.components.device_tracker.config_entry path is a
# DeprecatedAlias since ~HA 2025.6 and will be removed in HA 2027.6
# ("The deprecated alias ScannerEntity was used from
# keenetic_router_pro" log warning). The root export has existed for
# years, so this stays compatible with older HA cores too.
from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .const import (
    DOMAIN,
    DATA_COORDINATOR,
    DATA_PING_COORDINATOR,
    CONF_TRACKED_CLIENTS,
    CONF_LINK_STATE_FALLBACK,
    DEFAULT_LINK_STATE_FALLBACK,
)
from .coordinator import KeeneticCoordinator, KeeneticPingCoordinator
from .entity import ClientEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic Router Pro device trackers from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: KeeneticCoordinator = data[DATA_COORDINATOR]
    ping_coordinator: KeeneticPingCoordinator = data.get(DATA_PING_COORDINATOR)  # Note: get, might not exist
    entities: list[KeeneticClientTracker] = []

    tracked_clients = entry.data.get(CONF_TRACKED_CLIENTS, [])

    if not tracked_clients:
        return

    # Issue #48: read the link-state-fallback option once at setup.
    # Resolution chain: options (set via Options flow) -> data (set
    # at initial setup form) -> hard-coded default in const.py. The
    # tracker uses this to decide whether router-reported link state
    # acts as a backup signal when ICMP fails. Options-flow changes
    # trigger an integration reload, which re-runs this setup, so we
    # don't need to subscribe to live option changes here.
    link_state_fallback = entry.options.get(
        CONF_LINK_STATE_FALLBACK,
        entry.data.get(CONF_LINK_STATE_FALLBACK, DEFAULT_LINK_STATE_FALLBACK),
    )

    seen_macs: set[str] = set()

    for client_info in tracked_clients:
        if not isinstance(client_info, dict):
            continue
            
        mac = str(client_info.get("mac") or "").lower()
        if not mac or mac in seen_macs:
            continue
        seen_macs.add(mac)

        label = client_info.get("name") or mac.upper()

        entities.append(
            KeeneticClientTracker(
                coordinator=coordinator,
                ping_coordinator=ping_coordinator,
                entry=entry,
                mac=mac,
                label=label,
                initial_ip=client_info.get("ip"),
                link_state_fallback=link_state_fallback,
            )
        )

    if entities:
        async_add_entities(entities)


class KeeneticClientTracker(ClientEntity, ScannerEntity):
    """Device tracker entity representing a tracked client."""
    _attr_should_poll = False
    _attr_entity_category = None  # Diagnostic altında değil, ayrı göster

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        ping_coordinator: KeeneticPingCoordinator | None,
        entry: ConfigEntry,
        mac: str,
        label: str,
        initial_ip: str | None = None,
        link_state_fallback: bool = DEFAULT_LINK_STATE_FALLBACK,
    ) -> None:
        ClientEntity.__init__(
            self, 
            coordinator,
            entry.entry_id,
            entry.title,
            mac,
            label,
            initial_ip,
            ping_coordinator
        )
        self._main_coordinator = coordinator
        self._ping_coordinator = ping_coordinator
        self._mac = mac.lower()
        self._label = label
        self._initial_ip = initial_ip
        # Issue #48: when ICMP fails, fall back to the router's own
        # link-state report. Catches devices that exist on the LAN but
        # are unreachable from HA due to routing / firewall (e.g.,
        # ESP32 on an isolated sub-LAN). Configurable via the options
        # flow; default is True because it strictly improves the
        # cross-subnet case without changing behaviour for users on a
        # flat LAN (the fallback only triggers AFTER ICMP fails).
        self._link_state_fallback = link_state_fallback
        self._attr_name = label

    async def async_added_to_hass(self) -> None:
        # super().async_added_to_hass() reaches CoordinatorEntity which
        # already registers ``self._handle_coordinator_update`` against
        # ``self.coordinator`` (== self._main_coordinator) via
        # ``self.async_on_remove(coordinator.async_add_listener(...))``.
        # Adding it again here would fire two state writes per
        # coordinator tick — that was the 1.7.32 fork bug. Only
        # register the ping coordinator listener, which super() knows
        # nothing about.
        await super().async_added_to_hass()

        # Ping coordinator'ı da dinle — her ping cycle'da state güncellensin
        self.async_on_remove(
            self._ping_coordinator.async_add_listener(
                self._handle_ping_update
            )
        )

    @callback
    def _handle_coordinator_update(self) -> None:
        client = self._client_from_main
        # Always push the current IP (or empty string) to the ping
        # coordinator. Two cases we must handle correctly:
        #
        #   1. client exists, ip is "0.0.0.0" or "" — router has
        #      cleared the lease. Forwarding the placeholder causes
        #      update_client_ip to DROP the stale entry from the
        #      ping map (because _is_valid_ip rejects it).
        #
        #   2. client row has disappeared entirely from the router
        #      response — the hotspot table no longer lists this MAC.
        #      Same cleanup path: pass an empty string and the stale
        #      IP is purged.
        #
        # Without both of these, the old address lingers in the ping
        # loop forever and the device tracker flips back to "home"
        # when some kernels answer ICMP to 0.0.0.0 or when the stale
        # IP happens to be owned by a different device now.
        ip = client.get("ip") if client else ""
        self._ping_coordinator.update_client_ip(self._mac, str(ip or ""))

        self.async_write_ha_state()

    @callback
    def _handle_ping_update(self) -> None:
        """Ping coordinator güncellendiğinde state'i yaz."""
        self.async_write_ha_state()

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}"

    @property
    def mac_address(self) -> str:
        return self._mac

    @property
    def ip_address(self) -> str | None:
        client = self._client_from_main
        if client:
            ip = client.get("ip")
            if ip:
                return str(ip)
        
        return self._initial_ip

    @property
    def hostname(self) -> str | None:
        client = self._client_from_main
        if not client:
            return self._label

        name = client.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        h = client.get("hostname")
        if isinstance(h, str) and h.strip():
            return h.strip()
        return self._label

    @property
    def source_type(self) -> SourceType:
        return SourceType.ROUTER

    @property
    def _is_apple_device(self) -> bool:
        name = self._label or ""
        name_lower = name.lower()
        return any(kw in name_lower for kw in ("apple", "iphone", "ipad"))

    def _router_says_connected(self) -> bool:
        """Return True if the router's client table says we're online.

        Used as a fallback signal when ICMP fails. Both ``link=up`` and
        ``active=true`` are accepted because Keenetic firmwares disagree
        on which field is authoritative for cross-subnet hosts. Either
        is sufficient — we OR them, not AND.
        """
        client = self._client_from_main
        if not client:
            return False
        link = str(client.get("link") or "").lower()
        if link == "up":
            return True
        active = client.get("active")
        if isinstance(active, bool):
            return active
        if isinstance(active, str):
            return active.lower() in ("true", "yes", "1", "up", "online")
        return bool(active)

    @property
    def is_connected(self) -> bool:
        if self._is_apple_device:
            # Apple devices sleep aggressively and stop answering ICMP
            # while otherwise online — link-state is the only reliable
            # signal for them. Pre-existing behaviour, kept verbatim.
            client = self._client_from_main
            if client:
                return str(client.get("link", "")).lower() == "up"
            return False

        # Non-Apple devices: ICMP is the primary signal. If a device
        # answers ICMP, it's definitively online — no need to consult
        # the router.
        ping_results = self._ping_coordinator.data or {}
        if ping_results.get(self._mac, False):
            return True

        # ICMP failed. If the user has the link-state-fallback option
        # enabled (default ON), use the router's view as a secondary
        # signal. This catches the cross-subnet scenario from issue
        # #48: an ESP32 on 192.168.3.0/24 that HA can't reach via
        # ICMP but the router sees as link=up.
        #
        # Failure mode to be aware of: stale router entries (device
        # truly disconnected but link=up hasn't expired yet) will
        # produce a brief false-positive "home" reading. In practice
        # Keenetic updates link state promptly on disconnect, so this
        # window is small (seconds, not minutes).
        if self._link_state_fallback and self._router_says_connected():
            return True

        return False

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        client = self._client_from_main
        ping_results = self._ping_coordinator.data or {}

        # Build a human-readable "why are we home/away" attribute so the
        # operator can debug border cases (especially cross-subnet
        # devices where the answer comes from the fallback rather than
        # ICMP). ``presence_source`` is one of:
        #   "link_state" — Apple device, only link consulted
        #   "ping"       — ICMP succeeded, conclusive
        #   "router_link"— ICMP failed, router fallback engaged
        #   "icmp_only"  — ICMP failed, fallback disabled → away
        #   "unreachable"— ICMP failed, router also reports down
        if self._is_apple_device:
            client_link = (client or {}).get("link", "unknown")
            tracking_info: dict[str, Any] = {
                "tracking_method": "link_state",
                "presence_source": "link_state",
                "link_status": client_link,
            }
        else:
            ping_ok = bool(ping_results.get(self._mac, False))
            router_ok = self._router_says_connected()
            if ping_ok:
                presence_source = "ping"
            elif self._link_state_fallback and router_ok:
                presence_source = "router_link"
            elif router_ok:
                # Router says up but the user disabled the fallback —
                # we report away. Surface the conflict so it's visible.
                presence_source = "icmp_only"
            else:
                presence_source = "unreachable"
            tracking_info = {
                "tracking_method": "ping",
                "presence_source": presence_source,
                "ping_status": "reachable" if ping_ok else "unreachable",
                "router_link_status": (client or {}).get("link", "unknown"),
                "router_active": (client or {}).get("active"),
                "link_state_fallback_enabled": self._link_state_fallback,
            }

        attrs: dict[str, Any] = {
            "label": self._label,
            **tracking_info,
        }
        
        if not client:
            attrs["ip"] = self._initial_ip
            return attrs

        iface = client.get("interface")
        if isinstance(iface, dict):
            iface_name = iface.get("name") or iface.get("id")
        else:
            iface_name = iface

        attrs.update({
            "ip": client.get("ip") or self._initial_ip,
            "hostname": client.get("hostname"),
            "interface": iface_name,
            "ssid": client.get("ssid"),
            "rssi": client.get("rssi"),
            "txrate": client.get("txrate"),
            "access": client.get("access"),
            "priority": client.get("priority"),
            "active": client.get("active"),
            "link": client.get("link"),
            "last-seen": client.get("last-seen"),
            "uptime": client.get("uptime"),
            "registered": client.get("registered"),
        })
        return {k: v for k, v in attrs.items() if v is not None}

    @property
    def _client_from_main(self) -> dict[str, Any] | None:
        clients = self._main_coordinator.data.get("clients", []) or []
        for item in clients:
            if str(item.get("mac") or "").lower() == self._mac:
                return item
        return None