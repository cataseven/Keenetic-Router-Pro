"""Mesh node sensors."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfDataRate, UnitOfTime, EntityCategory

from ..coordinator import KeeneticCoordinator
from ..entity import ControllerEntity, MeshEntity
from ..utils import clamp_percent, safe_float, safe_int
from .monotonic import MonotonicUptimeMixin


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


class KeeneticMeshUptimeSensor(MeshEntity, MonotonicUptimeMixin, SensorEntity):
    """Mesh node uptime sensor."""
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_has_entity_name = True
    _attr_translation_key = "uptime"
    _attr_icon = "mdi:timer-outline"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    # TOTAL_INCREASING (not MEASUREMENT): mesh node uptime resets to
    # zero on extender reboot. Matches router/PPPoE/WireGuard rationale.
    # Issue #60: the mws/member fallback feeds this from the same
    # hotspot rows as client uptime, so it inherits the same jitter —
    # MonotonicUptimeMixin holds the high-water mark across small dips.
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_suggested_display_precision = 0

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
    def native_value(self) -> int | None:
        node = self._node
        if node:
            uptime = node.get("uptime")
            if uptime not in (None, "", "unknown", "Unknown"):
                return self._clamp_monotonic(safe_int(uptime))
        return None


class KeeneticMeshClientsSensor(MeshEntity, SensorEntity):
    """Mesh node active clients sensor."""
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
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
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
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
            return safe_float(node.get("cpuload"))
        return None


class KeeneticMeshMemorySensor(MeshEntity, SensorEntity):
    """Mesh node memory usage percentage sensor."""
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
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
                    used = safe_float(part_used)
                    total = safe_float(part_total)
                    if used is not None and total is not None and total > 0:
                        return clamp_percent(round(used * 100.0 / total, 1))
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
    
class KeeneticMeshPortSensor(MeshEntity, SensorEntity):
    """Individual mesh node port sensor."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:ethernet"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        node_cid: str,
        port_label: str,
    ) -> None:
        """Initialize individual port sensor."""
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)
        self._port_label = port_label

    @property
    def name(self) -> str:
        """Return name for the sensor."""
        return f"Port {self._port_label}"

    @property
    def unique_id(self) -> str:
        """Return unique ID for the sensor."""
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_port_{self._port_label}_v2"

    @property
    def native_value(self) -> str:
        """Return port state."""
        node = self._node
        if not node:
            return "unknown"

        ports = node.get("port", [])
        for port in ports:
            if port.get("label") == self._port_label:
                return port.get("link", "unknown")

        return "not_found"

    @property
    def icon(self) -> str:
        """Return icon based on port state."""
        state = self.native_value
        if state == "up":
            return "mdi:ethernet"
        if state == "down":
            return "mdi:ethernet-off"
        return "mdi:ethernet"

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return additional port attributes."""
        node = self._node
        if not node:
            return None

        ports = node.get("port", [])
        for port in ports:
            if port.get("label") == self._port_label:
                attrs = {
                    "label": port.get("label"),
                    "appearance": port.get("appearance"),
                }
                if port.get("link") == "up":
                    attrs["speed"] = port.get("speed")
                    attrs["duplex"] = port.get("duplex")
                return attrs

        return None

class KeeneticMeshPortSpeedSensor(MeshEntity, SensorEntity):
    """Negotiated link speed for a mesh-node physical port.

    Mirrors ``KeeneticPortSpeedSensor`` (introduced as a controller-side
    sensor) for each mesh extender's ports. Exposed as a separate
    numeric entity from the existing combined ``KeeneticMeshPortSensor``
    so HA's long-term statistics can graph negotiated speed cleanly
    over time (the combined sensor's state is a string like "up",
    which statistics can't aggregate).

    The "available" property is wired to the port's link state — when
    a cable is unplugged the entity goes ``unavailable`` rather than
    reporting 0 Mbps, which keeps the statistics history honest.
    """
    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.DATA_RATE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = UnitOfDataRate.MEGABITS_PER_SECOND
    _attr_icon = "mdi:speedometer"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_suggested_display_precision = 0
    # NOTE: enabled-by-default, mirroring the controller-side
    # ``KeeneticPortSpeedSensor``. An earlier draft of this class
    # hid mesh-node port speeds in the disabled list to keep the
    # entity registry tidy on multi-port extenders, but that broke
    # the user expectation that "if my main router shows speed for
    # each port, so should each mesh node". Symmetry beats tidiness
    # here — users who don't want every port can still disable the
    # ones they don't care about individually.

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        node_cid: str,
        port_label: str,
    ) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)
        self._port_label = port_label

    @property
    def name(self) -> str:
        return f"Port {self._port_label} Speed"

    @property
    def unique_id(self) -> str:
        # Match the existing mesh port-state sensor's id-shaping so
        # nothing accidentally collides on routers whose CID has
        # colons / hyphens in it.
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_port_{self._port_label}_speed"

    def _port_data(self) -> dict[str, Any] | None:
        node = self._node
        if not node:
            return None
        for port in node.get("port", []) or []:
            if port.get("label") == self._port_label:
                return port
        return None

    @property
    def available(self) -> bool:
        if not super().available:
            return False
        port = self._port_data()
        return port is not None and port.get("link") == "up"

    @property
    def native_value(self) -> float | None:
        port = self._port_data()
        if port is None or port.get("link") != "up":
            return None
        speed = port.get("speed")
        if speed is None:
            return None
        try:
            return float(speed)
        except (TypeError, ValueError):
            return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        port = self._port_data()
        if not port:
            return None
        return {
            "duplex": port.get("duplex"),
            "link": port.get("link"),
        }
