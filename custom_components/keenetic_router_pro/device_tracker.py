"""Device tracker (presence) for Keenetic Router Pro."""
from __future__ import annotations
from typing import Any
from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.components.device_tracker import SourceType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .const import DOMAIN, DATA_COORDINATOR, DATA_PING_COORDINATOR, CONF_TRACKED_CLIENTS
from .coordinator import KeeneticCoordinator, KeeneticPingCoordinator
from .entity import ControllerEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic Router Pro device trackers from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: KeeneticCoordinator = data[DATA_COORDINATOR]
    ping_coordinator: KeeneticPingCoordinator = data[DATA_PING_COORDINATOR]
    entities: list[KeeneticClientTracker] = []

    # Sadece config'de belirtilen tracked client'ları ekle
    tracked_clients = entry.data.get(CONF_TRACKED_CLIENTS, [])

    if not tracked_clients:
        return

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
            )
        )

    if entities:
        async_add_entities(entities)


class KeeneticClientTracker(ControllerEntity, ScannerEntity):
    """Device tracker entity representing a tracked client."""
    _attr_should_poll = False
    _attr_entity_category = None  # Diagnostic altında değil, ayrı göster

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        ping_coordinator: KeeneticPingCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
        initial_ip: str | None = None,
    ) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._main_coordinator = coordinator
        self._ping_coordinator = ping_coordinator
        self._mac = mac.lower()
        self._label = label
        self._initial_ip = initial_ip
        self._attr_name = label

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        
        self.async_on_remove(
            self._main_coordinator.async_add_listener(
                self._handle_coordinator_update
            )
        )
        # Ping coordinator'ı da dinle — her ping cycle'da state güncellensin
        self.async_on_remove(
            self._ping_coordinator.async_add_listener(
                self._handle_ping_update
            )
        )

    @callback
    def _handle_coordinator_update(self) -> None:
        client = self._client_from_main
        if client:
            ip = client.get("ip")
            if ip:
                self._ping_coordinator.update_client_ip(self._mac, str(ip))
        
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

    @property
    def is_connected(self) -> bool:
        if self._is_apple_device:
            client = self._client_from_main
            if client:
                return str(client.get("link", "")).lower() == "up"
            return False
        else:
            ping_results = self._ping_coordinator.data or {}
            return ping_results.get(self._mac, False) 

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        client = self._client_from_main
        ping_results = self._ping_coordinator.data or {}
        
        if self._is_apple_device:
            client_link = (self._client_from_main or {}).get("link", "unknown")
            tracking_info: dict[str, Any] = {
                "tracking_method": "link_state",
                "link_status": client_link,
            }
        else:
            tracking_info = {
                "tracking_method": "ping",
                "ping_status": "reachable" if ping_results.get(self._mac, False) else "unreachable",
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
