"""Device tracker (presence) for Keenetic Router Pro."""

from __future__ import annotations

from typing import Any

from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.components.device_tracker import SourceType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, DATA_COORDINATOR, DATA_PING_COORDINATOR, CONF_TRACKED_CLIENTS
from .coordinator import KeeneticCoordinator, KeeneticPingCoordinator


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
        # Hiç tracked client yoksa entity ekleme
        return

    seen_macs: set[str] = set()

    for client_info in tracked_clients:
        if not isinstance(client_info, dict):
            continue
            
        mac = str(client_info.get("mac") or "").lower()
        if not mac or mac in seen_macs:
            continue
        seen_macs.add(mac)

        # Kayıtlı ismi al, yoksa MAC kullan
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


class KeeneticClientTracker(CoordinatorEntity, ScannerEntity):
    """Device tracker entity representing a tracked client."""

    _attr_should_poll = False

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        ping_coordinator: KeeneticPingCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
        initial_ip: str | None = None,
    ) -> None:
        # Ping coordinator'ı ana coordinator olarak kullan
        super().__init__(ping_coordinator)
        self._main_coordinator = coordinator
        self._ping_coordinator = ping_coordinator
        self._entry = entry
        self._mac = mac.lower()
        self._label = label
        self._initial_ip = initial_ip
        self._attr_name = label

    async def async_added_to_hass(self) -> None:
        """Entity Home Assistant'a eklendiğinde."""
        await super().async_added_to_hass()
        
        # Ana coordinator'dan da güncellemeleri dinle
        self.async_on_remove(
            self._main_coordinator.async_add_listener(
                self._handle_coordinator_update
            )
        )

    @callback
    def _handle_coordinator_update(self) -> None:
        """Ana coordinator güncellendiğinde IP adresini güncelle."""
        client = self._client_from_main
        if client:
            ip = client.get("ip")
            if ip:
                self._ping_coordinator.update_client_ip(self._mac, str(ip))
        
        self.async_write_ha_state()

    # ---- Core properties ----

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_client_{self._mac}"

    @property
    def mac_address(self) -> str:
        return self._mac

    @property
    def ip_address(self) -> str | None:
        """Return current IP address."""
        # Önce ana coordinator'dan güncel IP'yi al
        client = self._client_from_main
        if client:
            ip = client.get("ip")
            if ip:
                return str(ip)
        
        # Yoksa başlangıç IP'sini kullan
        return self._initial_ip

    @property
    def hostname(self) -> str | None:
        """HA'nin de göreceği host adı (label > hostname)."""
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
    def is_connected(self) -> bool:
        """Return True if client is considered connected (home) based on ping.
        
        Ping sonucuna göre:
          ping başarılı  -> home
          ping başarısız -> not_home
        """
        # Ping coordinator'dan sonucu al
        ping_results = self._ping_coordinator.data or {}
        return ping_results.get(self._mac, False)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        client = self._client_from_main
        ping_results = self._ping_coordinator.data or {}
        
        attrs: dict[str, Any] = {
            "label": self._label,
            "ping_status": "reachable" if ping_results.get(self._mac, False) else "unreachable",
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
            # debug için
            "active": client.get("active"),
            "link": client.get("link"),
            "last-seen": client.get("last-seen"),
            "uptime": client.get("uptime"),
            "registered": client.get("registered"),
        })
        return {k: v for k, v in attrs.items() if v is not None}

    @property
    def device_info(self) -> dict[str, Any]:
        """Tüm client entity'lerini router device'ı altında grupla."""
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": self._entry.title,
            "manufacturer": "Keenetic",
        }

    # ---- Helper ----

    @property
    def _client_from_main(self) -> dict[str, Any] | None:
        """Ana coordinator'dan client bilgisini al."""
        clients = self._main_coordinator.data.get("clients", []) or []
        for item in clients:
            if str(item.get("mac") or "").lower() == self._mac:
                return item
        return None
