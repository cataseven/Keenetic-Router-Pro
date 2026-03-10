"""Binary sensors for Keenetic Router Pro (Mesh AP status)."""
from __future__ import annotations
from typing import Any
from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorDeviceClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .const import DOMAIN, DATA_COORDINATOR
from .coordinator import KeeneticCoordinator
from .entity import MeshEntity, ControllerEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic Router Pro binary sensors from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: KeeneticCoordinator = data[DATA_COORDINATOR]
    entities: list[BinarySensorEntity] = []

    entities.append(KeeneticControllerUpdateSensor(coordinator, entry))

    # Mesh node'lar için binary sensor
    mesh_nodes = coordinator.data.get("mesh_nodes", [])
    for node in mesh_nodes:
        node_cid = node.get("cid") or node.get("id")
        if node_cid:
            entities.append(KeeneticMeshNodeSensor(coordinator, entry, node_cid))
            entities.append(KeeneticMeshUpdateSensor(coordinator, entry, node_cid))

    if entities:
        async_add_entities(entities)


class KeeneticMeshNodeSensor(MeshEntity, BinarySensorEntity):
    """Binary sensor for mesh/extender node connectivity status."""
    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        node_cid: str,
    ) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_connect"

    @property
    def name(self) -> str:
        return f"Connected"

    @property
    def is_on(self) -> bool:
        node = self._node
        if node:
            return node.get("connected", False)
        return False

    @property
    def icon(self) -> str:
        node = self._node
        if node:
            mode = node.get("mode", "")
            if mode == "extender":
                return "mdi:access-point-network"
            elif mode == "repeater":
                return "mdi:wifi-sync"
        return "mdi:access-point"

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        node = self._node
        if not node:
            return None

        return {
            "cid": self._node_cid,
            "mac": node.get("mac"),
            "ip": node.get("ip"),
            "model": node.get("model"),
            "mode": node.get("mode"),
            "uptime": node.get("uptime"),
            "cpuload": node.get("cpuload"),
            "memory": node.get("memory"),
            "firmware": node.get("firmware"),
            "firmware_available": node.get("firmware_available"),
            "associations": node.get("associations"),
            "rci_errors": node.get("rci_errors"),
        }
    

class KeeneticControllerUpdateSensor(ControllerEntity, BinarySensorEntity):
    """Binary sensor for main controller firmware update availability."""
    
    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.UPDATE
    _attr_icon = "mdi:package-up"

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
    ) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_controller_update"

    @property
    def name(self) -> str:
        return "Update Available"

    @property
    def is_on(self) -> bool:
        """Return True if firmware update is available for controller."""
        system = self.coordinator.data.get("system", {}) or {}
        
        current = system.get("title") or system.get("release")
        available = system.get("fw-available") or system.get("release-available")
        
        if not available or not current:
            return False
        
        if available == current:
            return False
        
        channel = system.get("fw-update-sandbox") or system.get("sandbox", "stable")
        if channel != "stable":
            return False
        
        return True

    @property
    def icon(self) -> str:
        if self.is_on:
            return "mdi:update"
        return "mdi:check-circle"

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        system = self.coordinator.data.get("system", {}) or {}
        
        current = system.get("title") or system.get("release")
        available = system.get("fw-available") or system.get("release-available")
        
        attrs = {
            "current_version": current,
            "update_channel": system.get("fw-update-sandbox") or system.get("sandbox"),
        }
        
        if available:
            attrs["available_version"] = available
        
        return attrs
    
class KeeneticMeshUpdateSensor(MeshEntity, BinarySensorEntity):
    """Binary sensor for mesh/extender firmware update availability."""
    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.UPDATE

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        node_cid: str,
    ) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "").replace(":", "")[:16]
        return f"{self._entry_id}_mesh_{safe_cid}_update"

    @property
    def name(self) -> str:
        return f"Update Available"

    @property
    def is_on(self) -> bool:
        node = self._node
        if node:
            current = node.get("firmware")
            available = node.get("firmware_available")
            if current and available and current != available:
                return True
        return False

    @property
    def icon(self) -> str:
        if self.is_on:
            return "mdi:update"
        return "mdi:check-circle"

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        node = self._node
        if not node:
            return None
        return {
            "cid": self._node_cid,
            "model": node.get("model"),
            "current_version": node.get("firmware"),
            "available_version": node.get("firmware_available"),
        }