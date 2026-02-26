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
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, DATA_COORDINATOR
from .coordinator import KeeneticCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic Router Pro binary sensors from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: KeeneticCoordinator = data[DATA_COORDINATOR]

    entities: list[BinarySensorEntity] = []

    # Mesh node'lar için binary sensor
    mesh_nodes = coordinator.data.get("mesh_nodes", [])
    for node in mesh_nodes:
        node_cid = node.get("cid") or node.get("id")
        if node_cid:
            entities.append(KeeneticMeshNodeSensor(coordinator, entry, node_cid))
            entities.append(KeeneticMeshUpdateSensor(coordinator, entry, node_cid))

    if entities:
        async_add_entities(entities)


class KeeneticMeshNodeSensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor for mesh/extender node connectivity status."""

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        node_cid: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._node_cid = node_cid

    @property
    def _node(self) -> dict[str, Any] | None:
        """Get current node data from coordinator."""
        nodes = self.coordinator.data.get("mesh_nodes", [])
        for node in nodes:
            if (node.get("cid") or node.get("id")) == self._node_cid:
                return node
        return None

    @property
    def unique_id(self) -> str:
        # CID'den güvenli unique id oluştur
        safe_cid = self._node_cid.replace("-", "").replace(":", "")[:16]
        return f"{self._entry.entry_id}_mesh_{safe_cid}"

    @property
    def name(self) -> str:
        node = self._node
        if node:
            node_name = node.get("name") or node.get("mac") or self._node_cid
            return f"Mesh - {node_name}"
        return f"Mesh - {self._node_cid}"

    @property
    def is_on(self) -> bool:
        """Return True if mesh node is connected."""
        node = self._node
        if node:
            return node.get("connected", False)
        return False

    @property
    def icon(self) -> str:
        """Return icon based on node mode."""
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

    @property
    def device_info(self) -> dict[str, Any]:
        """Group under main router device."""
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": self._entry.title,
            "manufacturer": "Keenetic",
        }


class KeeneticMeshUpdateSensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor for mesh/extender firmware update availability."""

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.UPDATE

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        node_cid: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._node_cid = node_cid

    @property
    def _node(self) -> dict[str, Any] | None:
        """Get current node data from coordinator."""
        nodes = self.coordinator.data.get("mesh_nodes", [])
        for node in nodes:
            if (node.get("cid") or node.get("id")) == self._node_cid:
                return node
        return None

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "").replace(":", "")[:16]
        return f"{self._entry.entry_id}_mesh_{safe_cid}_update"

    @property
    def name(self) -> str:
        node = self._node
        if node:
            node_name = node.get("name") or node.get("mac") or self._node_cid
            return f"Mesh - {node_name} Update Available"
        return f"Mesh - {self._node_cid} Update Available"

    @property
    def is_on(self) -> bool:
        """Return True if firmware update is available."""
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

    @property
    def device_info(self) -> dict[str, Any]:
        """Group under main router device."""
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": self._entry.title,
            "manufacturer": "Keenetic",
        }
