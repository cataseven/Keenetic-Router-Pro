"""WireGuard VPN sensors."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfInformation, UnitOfTime, EntityCategory

from ..coordinator import KeeneticCoordinator
from ..entity import ControllerEntity


class _BaseWgSensor(ControllerEntity, SensorEntity):
    """Base class for WireGuard sensors."""
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, wg_name: str) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._wg_name = wg_name

    @property
    def _wg_profiles(self) -> dict[str, Any]:
        return self.coordinator.data.get("wireguard", {}).get("profiles", {}) or {}

    @property
    def _wg(self) -> dict[str, Any]:
        return self._wg_profiles.get(self._wg_name, {}) or {}

    @property
    def _wg_label(self) -> str:
        profile = self._wg
        label = profile.get("label")
        if isinstance(label, str) and label.strip():
            return label.strip()
        return self._wg_name


class KeeneticWgUptimeSensor(_BaseWgSensor):
    """WireGuard tunnel uptime sensor."""
    _attr_has_entity_name = True

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wg_{self._wg_name}_uptime"

    @property
    def name(self) -> str:
        return f"WireGuard {self._wg_label} Uptime"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfTime.SECONDS

    @property
    def native_value(self) -> int:
        for key in ("uptime", "uptime_sec", "uptime_seconds"):
            value = self._wg.get(key)
            if value in (None, "", "unknown", "Unknown"):
                continue
            try:
                return int(float(value))
            except (TypeError, ValueError):
                continue
        return 0


class KeeneticWgRxSensor(_BaseWgSensor):
    """WireGuard RX (received traffic) sensor."""
    _attr_has_entity_name = True

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wg_{self._wg_name}_rx"

    @property
    def name(self) -> str:
        return f"WireGuard {self._wg_label} RX"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfInformation.MEGABYTES

    @property
    def native_value(self) -> float | None:
        for key in ("rxbytes", "rx", "received"):
            value = self._wg.get(key)
            if value in (None, ""):
                continue
            try:
                bytes_val = float(value)
                return round(bytes_val / (1024 * 1024), 2)
            except (TypeError, ValueError):
                continue
        return None


class KeeneticWgTxSensor(_BaseWgSensor):
    """WireGuard TX (sent traffic) sensor."""
    _attr_has_entity_name = True

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wg_{self._wg_name}_tx"

    @property
    def name(self) -> str:
        return f"WireGuard {self._wg_label} TX"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfInformation.MEGABYTES

    @property
    def native_value(self) -> float | None:
        for key in ("txbytes", "tx", "sent"):
            value = self._wg.get(key)
            if value in (None, ""):
                continue
            try:
                bytes_val = float(value)
                return round(bytes_val / (1024 * 1024), 2)
            except (TypeError, ValueError):
                continue
        return None