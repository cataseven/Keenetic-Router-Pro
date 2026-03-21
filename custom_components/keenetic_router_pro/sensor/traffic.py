"""Traffic sensors for LAN, WAN and generic interfaces."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfInformation, EntityCategory

from ..coordinator import KeeneticCoordinator
from ..entity import ControllerEntity


class KeeneticInterfaceRxSensor(ControllerEntity, SensorEntity):
    """Incoming traffic sensor for a specific interface."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:download-network"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        iface_name: str,
        iface_label: str,
    ) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._iface_name = iface_name
        self._iface_label = iface_label

    @property
    def unique_id(self) -> str:
        safe_name = self._iface_name.replace("/", "_").lower()
        return f"{self._entry_id}_iface_{safe_name}_rx"

    @property
    def name(self) -> str:
        return f"{self._iface_label} RX"

    @property
    def native_value(self) -> float | None:
        stats = self.coordinator.data.get("interface_stats", {})
        iface_stats = stats.get(self._iface_name, {})
        rxbytes = iface_stats.get("rxbytes", 0)
        if rxbytes:
            return round(float(rxbytes) / (1024 ** 3), 2)
        return 0.0

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        stats = self.coordinator.data.get("interface_stats", {})
        iface_stats = stats.get(self._iface_name, {})
        return {
            "interface": self._iface_name,
            "type": iface_stats.get("interface_type"),
            "link": iface_stats.get("link"),
            "state": iface_stats.get("state"),
            "rxpackets": iface_stats.get("rxpackets"),
            "rxerrors": iface_stats.get("rxerrors"),
            "rxdropped": iface_stats.get("rxdropped"),
        }


class KeeneticInterfaceTxSensor(ControllerEntity, SensorEntity):
    """Outgoing traffic sensor for a specific interface."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:upload-network"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        iface_name: str,
        iface_label: str,
    ) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._iface_name = iface_name
        self._iface_label = iface_label

    @property
    def unique_id(self) -> str:
        safe_name = self._iface_name.replace("/", "_").lower()
        return f"{self._entry_id}_iface_{safe_name}_tx"

    @property
    def name(self) -> str:
        return f"{self._iface_label} TX"

    @property
    def native_value(self) -> float | None:
        stats = self.coordinator.data.get("interface_stats", {})
        iface_stats = stats.get(self._iface_name, {})
        txbytes = iface_stats.get("txbytes", 0)
        if txbytes:
            return round(float(txbytes) / (1024 ** 3), 2)
        return 0.0

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        stats = self.coordinator.data.get("interface_stats", {})
        iface_stats = stats.get(self._iface_name, {})
        return {
            "interface": self._iface_name,
            "type": iface_stats.get("interface_type"),
            "link": iface_stats.get("link"),
            "state": iface_stats.get("state"),
            "txpackets": iface_stats.get("txpackets"),
            "txerrors": iface_stats.get("txerrors"),
            "txdropped": iface_stats.get("txdropped"),
        }


class KeeneticLanRxSensor(ControllerEntity, SensorEntity):
    """LAN (GigabitEthernet0) RX sensor."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:download-network"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._iface_name = "GigabitEthernet0"
        self._label = "LAN"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_lan_rx"

    @property
    def name(self) -> str:
        return f"{self._label} RX"

    @property
    def native_value(self) -> float | None:
        stats = self.coordinator.data.get("interface_stats", {})
        iface_stats = stats.get(self._iface_name, {})
        rxbytes = iface_stats.get("rxbytes", 0)
        if rxbytes:
            return round(float(rxbytes) / (1024 ** 3), 2)
        return 0.0


class KeeneticLanTxSensor(ControllerEntity, SensorEntity):
    """LAN (GigabitEthernet0) TX sensor."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:upload-network"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._iface_name = "GigabitEthernet0"
        self._label = "LAN"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_lan_tx"

    @property
    def name(self) -> str:
        return f"{self._label} TX"

    @property
    def native_value(self) -> float | None:
        stats = self.coordinator.data.get("interface_stats", {})
        iface_stats = stats.get(self._iface_name, {})
        txbytes = iface_stats.get("txbytes", 0)
        if txbytes:
            return round(float(txbytes) / (1024 ** 3), 2)
        return 0.0


class KeeneticWanRxSensor(ControllerEntity, SensorEntity):
    """WAN (GigabitEthernet1/ISP) RX sensor."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:download-network"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._iface_name = "GigabitEthernet1"
        self._label = "WAN"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_rx"

    @property
    def name(self) -> str:
        return f"{self._label} RX"

    @property
    def native_value(self) -> float | None:
        stats = self.coordinator.data.get("interface_stats", {})
        iface_stats = stats.get(self._iface_name, {})
        rxbytes = iface_stats.get("rxbytes", 0)
        if rxbytes:
            return round(float(rxbytes) / (1024 ** 3), 2)
        return 0.0


class KeeneticWanTxSensor(ControllerEntity, SensorEntity):
    """WAN (GigabitEthernet1/ISP) TX sensor."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:upload-network"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._iface_name = "GigabitEthernet1"
        self._label = "WAN"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_tx"

    @property
    def name(self) -> str:
        return f"{self._label} TX"

    @property
    def native_value(self) -> float | None:
        stats = self.coordinator.data.get("interface_stats", {})
        iface_stats = stats.get(self._iface_name, {})
        txbytes = iface_stats.get("txbytes", 0)
        if txbytes:
            return round(float(txbytes) / (1024 ** 3), 2)
        return 0.0