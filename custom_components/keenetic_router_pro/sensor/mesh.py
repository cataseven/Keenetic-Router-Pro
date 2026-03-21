"""Mesh node sensors."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTime, EntityCategory

from ..coordinator import KeeneticCoordinator
from ..entity import ControllerEntity, MeshEntity


class KeeneticMeshSystemStateSensor(ControllerEntity, SensorEntity):
    """Mesh system overall state sensor."""
    _attr_has_entity_name = True
    _attr_name = "Mesh System State"
    _attr_icon = "mdi:access-point-network"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_mesh_system_state"

    @property
    def native_value(self) -> str:
        """Return the overall mesh system state."""
        mesh_nodes = self.coordinator.data.get("mesh_nodes", [])

        if not mesh_nodes:
            return "no_nodes"

        connected = sum(1 for node in mesh_nodes if node.get("connected", False))
        total = len(mesh_nodes)

        if connected == 0:
            return "down"
        elif connected < total:
            return "problem"
        else:
            return "ok"

    @property
    def icon(self) -> str:
        """Return icon based on current state."""
        state = self.native_value
        if state == "ok":
            return "mdi:check-network"
        elif state == "problem":
            return "mdi:close-network"
        elif state == "down":
            return "mdi:network-off"
        else:
            return "mdi:help-network"

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return detailed mesh system information."""
        mesh_nodes = self.coordinator.data.get("mesh_nodes", [])

        if not mesh_nodes:
            return {
                "total_nodes": 0,
                "connected_nodes": 0,
                "disconnected_nodes": 0,
                "nodes": [],
            }

        connected = 0
        disconnected = 0
        nodes_detail = []

        for node in mesh_nodes:
            is_connected = node.get("connected", False)
            if is_connected:
                connected += 1
            else:
                disconnected += 1

            nodes_detail.append({
                "name": node.get("name") or node.get("mac", "Unknown"),
                "mac": node.get("mac"),
                "ip": node.get("ip"),
                "model": node.get("model"),
                "mode": node.get("mode"),
                "connected": is_connected,
                "firmware": node.get("firmware"),
                "associations": node.get("associations", 0),
            })

        total = len(mesh_nodes)
        health_percent = round((connected / total) * 100, 1) if total > 0 else 0

        return {
            "total_nodes": total,
            "connected_nodes": connected,
            "disconnected_nodes": disconnected,
            "health_percent": health_percent,
            "state": self.native_value,
            "nodes": nodes_detail,
        }


class KeeneticMeshUptimeSensor(MeshEntity, SensorEntity):
    """Mesh node uptime sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "uptime"
    _attr_icon = "mdi:timer-outline"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, node_cid: str) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_uptime_v2"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfTime.SECONDS

    @property
    def native_value(self) -> int:
        node = self._node
        if node:
            uptime = node.get("uptime")
            if uptime not in (None, "", "unknown", "Unknown"):
                try:
                    return int(float(uptime))
                except (TypeError, ValueError):
                    pass
        return 0


class KeeneticMeshClientsSensor(MeshEntity, SensorEntity):
    """Mesh node active clients sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "mesh_clients"
    _attr_icon = "mdi:account-group"
    _attr_state_class = SensorStateClass.TOTAL
    _attr_suggested_display_precision = 0

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, node_cid: str) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_clients_v2"

    @property
    def native_value(self) -> int:
        node = self._node
        if node:
            associations = node.get("associations")
            if associations is not None:
                try:
                    return int(associations)
                except (TypeError, ValueError):
                    pass
        return 0

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
        }


class KeeneticMeshLocalIpSensor(MeshEntity, SensorEntity):
    """Sensor for local IP address of a mesh node."""
    _attr_has_entity_name = True
    _attr_name = "IP"
    _attr_icon = "mdi:ip-network"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        node_cid: str,
        ip_address: str,
    ) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)
        self._ip_address = ip_address

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_local_ip_v2"

    @property
    def native_value(self) -> str | None:
        node = self._node
        if node and node.get("ip"):
            return node.get("ip")
        return self._ip_address


class KeeneticMeshCpuLoadSensor(MeshEntity, SensorEntity):
    """Mesh node CPU load sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "cpu_load"
    _attr_native_unit_of_measurement = "%"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:cpu-64-bit"

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, node_cid: str) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_cpu_load_v2"

    @property
    def native_value(self) -> float | None:
        node = self._node
        if node:
            cpuload = node.get("cpuload")
            if cpuload is not None:
                try:
                    return float(cpuload)
                except (TypeError, ValueError):
                    pass
        return None


class KeeneticMeshMemorySensor(MeshEntity, SensorEntity):
    """Mesh node memory usage percentage sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "memory_usage"
    _attr_native_unit_of_measurement = "%"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:memory"

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, node_cid: str) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_memory_v2"

    @property
    def native_value(self) -> float | None:
        node = self._node
        if node:
            memory = node.get("memory")
            if isinstance(memory, str) and "/" in memory:
                try:
                    part_used, part_total = memory.split("/", 1)
                    used = float(part_used)
                    total = float(part_total)
                    if total > 0:
                        return round(used * 100.0 / total, 1)
                except (ValueError, TypeError):
                    pass
        return None


class KeeneticMeshFirmwareVersionSensor(MeshEntity, SensorEntity):
    """Current firmware version sensor for a mesh node."""
    _attr_has_entity_name = True
    _attr_translation_key = "mesh_firmware_version"
    _attr_icon = "mdi:package-variant-closed"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, node_cid: str) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_firmware_version_v2"

    @property
    def native_value(self) -> str | None:
        node = self._node
        if node:
            return node.get("firmware")
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        node = self._node
        if not node:
            return None
        attrs: dict[str, Any] = {}
        if node.get("firmware_available"):
            attrs["firmware_available"] = node["firmware_available"]
        if node.get("hw_id"):
            attrs["hardware_id"] = node["hw_id"]
        if node.get("model"):
            attrs["model"] = node["model"]
        return attrs if attrs else None