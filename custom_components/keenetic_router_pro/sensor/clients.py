"""Client sensors for connected/disconnected devices."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry

from ..coordinator import KeeneticCoordinator
from ..entity import ControllerEntity


class KeeneticConnectedClientsSensor(ControllerEntity, SensorEntity):
    """Connected clients count sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "connected_clients"
    _attr_icon = "mdi:devices"
    _attr_state_class = SensorStateClass.TOTAL
    _attr_suggested_display_precision = 0

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_connected_clients_v2"

    @property
    def native_value(self) -> int:
        stats = self.coordinator.data.get("client_stats", {})
        return stats.get("connected", 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        stats = self.coordinator.data.get("client_stats", {})
        return {
            "total": stats.get("total", 0),
            "per_ap": stats.get("per_ap", {}),
        }


class KeeneticRouterClientsSensor(ControllerEntity, SensorEntity):
    """Clients directly connected to main router sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "router_clients"
    _attr_icon = "mdi:devices"
    _attr_state_class = SensorStateClass.TOTAL
    _attr_suggested_display_precision = 0

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_router_clients_v2"

    @property
    def native_value(self) -> int:
        stats = self.coordinator.data.get("client_stats", {})
        total_connected = stats.get("connected", 0)

        mesh_nodes = self.coordinator.data.get("mesh_nodes", [])
        mesh_associations = 0
        for node in mesh_nodes:
            try:
                mesh_associations += int(node.get("associations", 0))
            except (TypeError, ValueError):
                pass

        return max(total_connected - mesh_associations, 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        stats = self.coordinator.data.get("client_stats", {})
        mesh_nodes = self.coordinator.data.get("mesh_nodes", [])

        mesh_associations = 0
        for node in mesh_nodes:
            try:
                mesh_associations += int(node.get("associations", 0))
            except (TypeError, ValueError):
                pass

        return {
            "total_connected": stats.get("connected", 0),
            "mesh_clients": mesh_associations,
            "per_ap": stats.get("per_ap", {}),
        }


class KeeneticDisconnectedClientsSensor(ControllerEntity, SensorEntity):
    """Disconnected (known) clients count sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "disconnected_clients"
    _attr_icon = "mdi:lan-disconnect"
    _attr_state_class = SensorStateClass.TOTAL
    _attr_suggested_display_precision = 0

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_disconnected_clients"

    @property
    def native_value(self) -> int:
        stats = self.coordinator.data.get("client_stats", {})
        return stats.get("disconnected", 0)


class KeeneticExtenderCountSensor(ControllerEntity, SensorEntity):
    """Mesh extender/repeater count sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "extender_count"
    _attr_icon = "mdi:access-point-network"
    _attr_state_class = SensorStateClass.TOTAL
    _attr_suggested_display_precision = 0

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_extender_count"

    @property
    def native_value(self) -> int:
        mesh_nodes = self.coordinator.data.get("mesh_nodes", [])
        return len(mesh_nodes)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        mesh_nodes = self.coordinator.data.get("mesh_nodes", [])
        connected = sum(1 for n in mesh_nodes if n.get("connected", False))
        disconnected = len(mesh_nodes) - connected

        node_list = []
        for node in mesh_nodes:
            node_list.append({
                "name": node.get("name"),
                "ip": node.get("ip"),
                "mode": node.get("mode"),
                "connected": node.get("connected"),
            })

        return {
            "connected": connected,
            "disconnected": disconnected,
            "nodes": node_list,
        }