"""USB storage sensors for main router and mesh nodes."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfInformation, EntityCategory

from ..coordinator import KeeneticCoordinator
from ..entity import ControllerEntity, MeshEntity


class KeeneticUsbStorageSensor(ControllerEntity, SensorEntity):
    """USB storage sensor."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:usb-flash-drive"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, device_id: str) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._device_id = device_id

    @property
    def _device(self) -> dict[str, Any] | None:
        devices = self.coordinator.data.get("usb_storage", [])
        for device in devices:
            if device.get("id") == self._device_id:
                return device
        return None

    @property
    def unique_id(self) -> str:
        safe_id = self._device_id.replace("/", "_").replace(" ", "_").lower()
        return f"{self._entry_id}_usb_{safe_id}"

    @property
    def name(self) -> str:
        device = self._device
        if device:
            label = device.get("label") or device.get("model") or self._device_id
            return f"USB - {str(label).title()}"
        return f"USB - {str(self._device_id).title()}"

    @property
    def native_unit_of_measurement(self) -> str:
        return PERCENTAGE

    @property
    def native_value(self) -> float | None:
        device = self._device
        if device:
            try:
                total = float(device.get("total", 0) or 0)
                free = float(device.get("free", 0) or 0)
            except (TypeError, ValueError):
                return None
            if total <= 0:
                return None
            used = total - free
            return round((used / total) * 100.0, 2)
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        device = self._device
        if not device:
            return None

        total = device.get("total", 0)
        used = device.get("used", 0)
        free = device.get("free", 0)

        percent_used = round((used / total) * 100, 1) if total > 0 else 0

        return {
            "device_id": self._device_id,
            "label": device.get("label"),
            "vendor": device.get("vendor"),
            "model": device.get("model"),
            "serial": device.get("serial"),
            "filesystem": device.get("filesystem"),
            "state": device.get("state"),
            "type": device.get("type"),
            "usb_version": device.get("usb_version"),
            "ejectable": device.get("ejectable"),
            "power_control": device.get("power_control"),
            "uuid": device.get("uuid"),
            "total_gb": round(float(total) / (1024 ** 3), 2),
            "used_gb": round(float(used) / (1024 ** 3), 2),
            "free_gb": round(float(free) / (1024 ** 3), 2),
            "percent_used": percent_used,
        }


class KeeneticMeshUsbStorageSensor(MeshEntity, SensorEntity):
    """USB storage sensor - on mesh node."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:usb-flash-drive"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        device_id: str,
        mesh_node_name: str | None = None,
        mesh_cid: str | None = None,
    ) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, mesh_cid or device_id)
        self._device_id = device_id
        self._mesh_node_name = mesh_node_name or "Unknown"
        self._mesh_cid = mesh_cid

    @property
    def _device(self) -> dict[str, Any] | None:
        devices = self.coordinator.data.get("mesh_usb", [])
        for device in devices:
            if device.get("id") == self._device_id:
                return device
        return None

    @property
    def unique_id(self) -> str:
        safe_id = self._device_id.replace("/", "_").replace(" ", "_").lower()
        safe_cid = (self._mesh_cid or "unknown").replace("-", "_").replace(":", "_")[:12]
        return f"{safe_cid}_usb_{safe_id}_v2"

    @property
    def name(self) -> str:
        device = self._device
        if device:
            label = device.get("label") or device.get("model") or self._device_id
            return f"USB - {self._mesh_node_name} - {label}"
        return f"USB - {self._mesh_node_name} - {self._device_id}"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfInformation.GIGABYTES

    @property
    def native_value(self) -> float | None:
        device = self._device
        if device:
            used = device.get("used", 0)
            if used:
                return round(float(used) / (1024 ** 3), 2)
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        device = self._device
        if not device:
            return None

        total = device.get("total", 0)
        used = device.get("used", 0)
        free = device.get("free", 0)

        percent_used = round((used / total) * 100, 1) if total > 0 else 0

        return {
            "device_id": self._device_id,
            "mesh_node": self._mesh_node_name,
            "mesh_cid": self._mesh_cid,
            "label": device.get("label"),
            "vendor": device.get("vendor"),
            "model": device.get("model"),
            "filesystem": device.get("filesystem"),
            "state": device.get("state"),
            "total_gb": round(float(total) / (1024 ** 3), 2) if total else 0,
            "used_gb": round(float(used) / (1024 ** 3), 2) if used else 0,
            "free_gb": round(float(free) / (1024 ** 3), 2) if free else 0,
            "percent_used": percent_used,
        }