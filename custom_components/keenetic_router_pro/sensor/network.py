"""Network sensors for WAN status, IP, PPPoE and connections."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorStateClass,
    SensorDeviceClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTime, UnitOfInformation, UnitOfDataRate, EntityCategory

from ..coordinator import KeeneticCoordinator
from ..entity import ControllerEntity, WanEntity
from ..utils import safe_float, safe_int
from .monotonic import MonotonicUptimeMixin


class KeeneticWanStatusSensor(ControllerEntity, SensorEntity):
    """WAN connection status sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "wan_status"

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_status"

    @property
    def native_value(self) -> str | None:
        wan = self.coordinator.data.get("wan_status", {})
        return wan.get("status", "down")

    @property
    def icon(self) -> str:
        status = self.native_value
        if status == "connected":
            return "mdi:web-check"
        if status == "link_up":
            return "mdi:web-remove"
        return "mdi:web-off"

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        wan = self.coordinator.data.get("wan_status", {})
        attrs: dict[str, Any] = {}
        if wan.get("interface"):
            attrs["interface"] = wan["interface"]
        if wan.get("type"):
            attrs["type"] = wan["type"]
        if wan.get("ip"):
            attrs["ip"] = wan["ip"]
        if wan.get("gateway"):
            attrs["gateway"] = wan["gateway"]
        if wan.get("link"):
            attrs["link"] = wan["link"]
        return attrs if attrs else None


class KeeneticWanIpSensor(ControllerEntity, SensorEntity):
    """WAN IP address sensor."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:ip-network"

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_ip"

    @property
    def name(self) -> str:
        return "WAN IP"

    @property
    def native_value(self) -> str | None:
        wan = self.coordinator.data.get("wan_status", {})
        return wan.get("ip")

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        wan = self.coordinator.data.get("wan_status", {})
        return {
            "interface": wan.get("interface"),
            "gateway": wan.get("gateway"),
            "status": wan.get("status"),
        }


class KeeneticPppoeUptimeSensor(ControllerEntity, MonotonicUptimeMixin, SensorEntity):
    """PPPoE connection uptime sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "pppoe_uptime"
    _attr_icon = "mdi:timer-outline"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    # TOTAL_INCREASING (not MEASUREMENT): PPPoE uptime is a monotonic
    # counter that resets to zero on every redial. See the rationale
    # on KeeneticUptimeSensor. Issue #60: MonotonicUptimeMixin shields
    # the recorder from sub-10% counter dips.
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_suggested_display_precision = 0

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_pppoe_uptime"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfTime.SECONDS

    @property
    def native_value(self) -> int | None:
        wan = self.coordinator.data.get("wan_status", {})
        uptime = wan.get("uptime")
        if uptime in (None, "", "unknown", "Unknown"):
            return None
        return self._clamp_monotonic(safe_int(uptime))

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        wan = self.coordinator.data.get("wan_status", {})
        return {
            "interface": wan.get("interface"),
            "type": wan.get("type"),
            "status": wan.get("status"),
            "ip": wan.get("ip"),
        }


class KeeneticActiveConnectionsSensor(ControllerEntity, SensorEntity):
    """Active connections count sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "active_connections"
    _attr_icon = "mdi:connection"
    _attr_state_class = SensorStateClass.TOTAL
    _attr_suggested_display_precision = 0

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_active_connections"

    @property
    def native_value(self) -> int:
        sys = self.coordinator.data.get("system", {}) or {}
        conntotal = sys.get("conntotal", 0)
        connfree = sys.get("connfree", 0)
        try:
            return int(conntotal) - int(connfree)
        except (TypeError, ValueError):
            return 0

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        sys = self.coordinator.data.get("system", {}) or {}
        try:
            conntotal = int(sys.get("conntotal", 0))
            connfree = int(sys.get("connfree", 0))
        except (TypeError, ValueError):
            conntotal = 0
            connfree = 0
        return {
            "total_capacity": conntotal,
            "free": connfree,
            "used_percent": round((conntotal - connfree) * 100.0 / conntotal, 1) if conntotal > 0 else 0,
        }


class KeeneticLocalIpSensor(ControllerEntity, SensorEntity):
    """Sensor for local IP address of the router/device."""
    _attr_has_entity_name = True
    _attr_name = "IP"
    _attr_icon = "mdi:ip-network"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, ip_address: str) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._ip_address = ip_address

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_local_ip"

    @property
    def native_value(self) -> str | None:
        return self._ip_address


class KeeneticMainPortSensor(ControllerEntity, SensorEntity):
    """Individual main router port sensor."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:ethernet"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        port_label: str,
    ) -> None:
        """Initialize individual port sensor."""
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._port_label = port_label

    @property
    def name(self) -> str:
        """Return name for the sensor."""
        return f"Port {self._port_label}"

    @property
    def unique_id(self) -> str:
        """Return unique ID for the sensor."""
        return f"{self._entry_id}_port_{self._port_label}"

    @property
    def native_value(self) -> str:
        """Return port state."""
        ports = self.coordinator.data.get("port_info", [])
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
        ports = self.coordinator.data.get("port_info", [])
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


class KeeneticPortSpeedSensor(ControllerEntity, SensorEntity):
    """Negotiated link speed for a physical port (10 / 100 / 1000 Mbps)."""
    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.DATA_RATE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = UnitOfDataRate.MEGABITS_PER_SECOND
    _attr_icon = "mdi:speedometer"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_suggested_display_precision = 0

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        port_label: str,
    ) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._port_label = port_label

    @property
    def name(self) -> str:
        return f"Port {self._port_label} Speed"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_port_{self._port_label}_speed"

    def _port_data(self) -> dict[str, Any] | None:
        """Return the port dict for this label, or None if not found."""
        for port in self.coordinator.data.get("port_info", []) or []:
            if port.get("label") == self._port_label:
                return port
        return None

    @property
    def available(self) -> bool:
        """Only available when coordinator is running AND port link is up."""
        if not super().available:
            return False
        port = self._port_data()
        return port is not None and port.get("link") == "up"

    @property
    def native_value(self) -> float | None:
        """Return negotiated link speed in Mbps, or None when link is down."""
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


# =============================================================================
# Per-WAN interface sensors
#
# One set of these is instantiated per entry in coordinator.data["wan_interfaces"].
# Each WAN becomes its own HA sub-device (see utils.get_wan_device_info).
# =============================================================================


class _WanSensorBase(WanEntity, SensorEntity):
    """Shared base for per-WAN SensorEntity classes."""
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        wan_id: str,
    ) -> None:
        WanEntity.__init__(self, coordinator, entry.entry_id, entry.title, wan_id)


class KeeneticWanProviderSensor(_WanSensorBase):
    """Provider / description shown as the entity name."""
    _attr_icon = "mdi:web"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_provider"

    @property
    def name(self) -> str:
        return "Provider"

    @property
    def native_value(self) -> str | None:
        wan = self._wan
        if not wan:
            return None
        return wan.get("description") or wan.get("interface_name") or self._wan_id


class KeeneticWanRoleSensor(_WanSensorBase):
    """Routing role: Default connection / Backup connection N."""
    _attr_icon = "mdi:sort-numeric-ascending"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_role"

    @property
    def name(self) -> str:
        return "Role"

    @property
    def native_value(self) -> str | None:
        wan = self._wan
        if not wan:
            return None
        return wan.get("role_label")

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        wan = self._wan
        if not wan:
            return None
        return {
            "priority": wan.get("priority"),
            "role_index": wan.get("role_index"),
            "defaultgw": wan.get("defaultgw"),
        }


class KeeneticWanInterfaceSensor(_WanSensorBase):
    """Underlying interface id (e.g. GigabitEthernet1/Vlan35)."""
    _attr_icon = "mdi:ethernet-cable"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_interface"

    @property
    def name(self) -> str:
        return "Interface"

    @property
    def native_value(self) -> str | None:
        wan = self._wan
        if not wan:
            return None
        # The physical/logical carrier (PPPoE `via`) is the most useful
        # value here; fall back to the WAN's own id for Ethernet WANs
        # and WireGuard tunnels that have no underlying interface.
        return wan.get("underlying") or wan.get("id")

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        wan = self._wan
        if not wan:
            return None
        return {
            "wan_id": wan.get("id"),
            "interface_name": wan.get("interface_name"),
            "type": wan.get("type"),
            "remote": wan.get("remote"),
            "mac": wan.get("mac"),
        }


class KeeneticWanPublicIpSensor(_WanSensorBase):
    """Public IP address of the WAN (PPPoE / DHCP / static)."""
    _attr_icon = "mdi:ip-network"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_public_ip"

    @property
    def name(self) -> str:
        return "Public IP"

    @property
    def native_value(self) -> str | None:
        wan = self._wan
        if not wan:
            return None
        return wan.get("ip")

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        wan = self._wan
        if not wan:
            return None
        return {
            "mask": wan.get("mask"),
            "remote": wan.get("remote"),
            "global": wan.get("global"),
        }


class KeeneticWanUptimeSensor(MonotonicUptimeMixin, _WanSensorBase):
    """Session uptime for the WAN, in seconds."""
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_icon = "mdi:timer-outline"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_device_class = SensorDeviceClass.DURATION
    # TOTAL_INCREASING: same rationale as router/PPPoE uptime — WAN
    # session uptime resets every time the uplink redials. Issue #60:
    # MonotonicUptimeMixin shields the recorder from sub-10% dips.
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_suggested_display_precision = 0

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_uptime"

    @property
    def name(self) -> str:
        return "Uptime"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfTime.SECONDS

    @property
    def native_value(self) -> int | None:
        wan = self._wan
        if not wan:
            return None
        up = wan.get("uptime")
        if up in (None, "", "unknown"):
            return None
        return self._clamp_monotonic(safe_int(up))


class _WanBytesBase(_WanSensorBase):
    """Shared RX/TX byte counter base."""
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = UnitOfInformation.BYTES
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _field = "rx_bytes"

    @property
    def native_value(self) -> int | None:
        wan = self._wan
        if not wan:
            return None
        # safe_int collapses NaN/inf + the TypeError/ValueError cases
        # the old code caught into one None-return path.
        return safe_int(wan.get(self._field))


class KeeneticWanRxBytesSensor(_WanBytesBase):
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_icon = "mdi:download"
    _field = "rx_bytes"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_rx_bytes"

    @property
    def name(self) -> str:
        return "RX Bytes"


class KeeneticWanTxBytesSensor(_WanBytesBase):
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_icon = "mdi:upload"
    _field = "tx_bytes"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_tx_bytes"

    @property
    def name(self) -> str:
        return "TX Bytes"


class _WanThroughputBase(_WanSensorBase):
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_device_class = SensorDeviceClass.DATA_RATE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = UnitOfDataRate.BYTES_PER_SECOND
    _attr_suggested_display_precision = 0
    _field = "rx_throughput"

    @property
    def native_value(self) -> float | None:
        wan = self._wan
        if not wan:
            return None
        return safe_float(wan.get(self._field))


class KeeneticWanRxThroughputSensor(_WanThroughputBase):
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_icon = "mdi:download-network"
    _field = "rx_throughput"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_rx_throughput"

    @property
    def name(self) -> str:
        return "RX Throughput"


class KeeneticWanTxThroughputSensor(_WanThroughputBase):
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_icon = "mdi:upload-network"
    _field = "tx_throughput"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_tx_throughput"

    @property
    def name(self) -> str:
        return "TX Throughput"
