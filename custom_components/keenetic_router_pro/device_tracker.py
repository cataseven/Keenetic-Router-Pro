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


class KeeneticClientTracker(ClientEntity, ScannerEntity):
    """Device tracker entity for tracked clients as separate devices."""
    _attr_should_poll = False
    _attr_entity_category = None
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        ping_coordinator: KeeneticPingCoordinator | None,
        entry: ConfigEntry,
        mac: str,
        label: str,
        initial_ip: str | None = None,
    ) -> None:
        # ВАЖНО: порядок аргументов должен соответствовать определению в ClientEntity
        ClientEntity.__init__(
            self, 
            coordinator,      # coordinator
            entry.entry_id,   # entry_id
            entry.title,      # title
            mac,              # mac
            label,            # label
            initial_ip,       # initial_ip
            ping_coordinator  # ping_coordinator (последний!)
        )
        self._attr_name = label

    async def async_added_to_hass(self) -> None:
        """When entity is added to hass."""
        await super().async_added_to_hass()
        
        # Listen to main coordinator updates
        self.async_on_remove(
            self.coordinator.async_add_listener(
                self._handle_coordinator_update
            )
        )
        
        # Listen to ping coordinator updates if available
        if self._ping_coordinator and hasattr(self._ping_coordinator, 'async_add_listener'):
            self.async_on_remove(
                self._ping_coordinator.async_add_listener(
                    self._handle_ping_update
                )
            )

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle main coordinator updates."""
        client = self._client
        if client:
            ip = client.get("ip")
            if ip and self._ping_coordinator and hasattr(self._ping_coordinator, 'update_client_ip'):
                self._ping_coordinator.update_client_ip(self._mac, str(ip))
        self.async_write_ha_state()

    @callback
    def _handle_ping_update(self) -> None:
        """Handle ping coordinator updates."""
        self.async_write_ha_state()

    @property
    def unique_id(self) -> str:
        """Return unique ID for entity."""
        return f"{self._entry_id}_client_{self._mac}"

    @property
    def mac_address(self) -> str:
        """Return MAC address."""
        return self._mac

    @property
    def source_type(self) -> SourceType:
        """Return source type."""
        return SourceType.ROUTER

    @property
    def is_connected(self) -> bool:
        """Return true if device is connected."""
        return super().is_connected

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return state attributes."""
        client = self._client
        
        tracking_info: dict[str, Any] = {}
        
        # Проверяем, что ping_coordinator - это объект
        if self._ping_coordinator and hasattr(self._ping_coordinator, 'data') and not self._is_apple_device:
            ping_results = self._ping_coordinator.data or {}
            tracking_info = {
                "tracking_method": "ping",
                "ping_status": "reachable" if ping_results.get(self._mac, False) else "unreachable",
            }
        else:
            client_link = (client or {}).get("link", "unknown")
            tracking_info = {
                "tracking_method": "link_state",
                "link_status": client_link,
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
            iface_type = iface.get("type")
        else:
            iface_name = iface
            iface_type = None

        attrs.update({
            "ip": client.get("ip") or self._initial_ip,
            "hostname": client.get("hostname"),
            "interface": iface_name,
            "interface_type": iface_type,
            "ssid": client.get("ssid"),
            "rssi": client.get("rssi"),
            "txrate": client.get("txrate"),
            "rxrate": client.get("rxrate"),
            "access": client.get("access"),
            "priority": client.get("priority"),
            "active": client.get("active"),
            "link": client.get("link"),
            "last-seen": client.get("last-seen"),
            "uptime": client.get("uptime"),
            "registered": client.get("registered"),
            "device_type": client.get("device_type"),
            "vendor": client.get("vendor"),
        })
        return {k: v for k, v in attrs.items() if v is not None}