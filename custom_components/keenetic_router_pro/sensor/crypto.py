"""Sensors for site-to-site IPsec tunnels (`crypto map` entries).

One set of these is instantiated per entry in
``coordinator.data["crypto_maps"]``. Each tunnel becomes its own HA
sub-device (see ``utils.get_crypto_map_device_info``), mirroring the
per-WAN model.

All sensor classes gracefully handle the "tunnel configured but not
yet established" state where the router response is missing the
``phase1`` and ``phase2_sa_list`` blocks entirely — in that case the
counter / throughput sensors return 0 (which is accurate: no SA
means no bytes) and the state sensors return whatever the router
reports (``UNDEFINED`` is common).
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorStateClass,
    SensorDeviceClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    UnitOfInformation,
    UnitOfDataRate,
    EntityCategory,
)

from ..coordinator import KeeneticCoordinator
from ..entity import CryptoMapEntity


class _CryptoMapSensorBase(CryptoMapEntity, SensorEntity):
    """Shared base for per-crypto-map SensorEntity classes."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        cmap_name: str,
    ) -> None:
        CryptoMapEntity.__init__(
            self, coordinator, entry.entry_id, entry.title, cmap_name
        )


# ---------- State sensors (diagnostic strings) ----------


class KeeneticCryptoMapStateSensor(_CryptoMapSensorBase):
    """Overall tunnel state (``UNDEFINED`` / ``CONNECTING`` /
    ``PHASE1_ONLY`` / ``PHASE2_ESTABLISHED`` / ...).

    This is the same field that powers the Connected binary_sensor,
    exposed here as a raw string for diagnostics and automation
    templates that need the exact state.
    """

    _attr_icon = "mdi:lan-connect"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_cmap_{self._cmap_name}_state"

    @property
    def name(self) -> str:
        return "Tunnel state"

    @property
    def native_value(self) -> str | None:
        cmap = self._cmap
        if cmap is None:
            return None
        return cmap.get("state")


class KeeneticCryptoMapIkeStateSensor(_CryptoMapSensorBase):
    """Phase-1 / IKE state.

    Distinct from the overall tunnel state: you can have IKE
    ``ESTABLISHED`` while the overall state is still ``PHASE1_ONLY``
    because phase-2 SA negotiation failed. That's exactly the case
    where this sensor is most useful for troubleshooting.
    """

    _attr_icon = "mdi:key-chain-variant"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_cmap_{self._cmap_name}_ike_state"

    @property
    def name(self) -> str:
        return "IKE state"

    @property
    def native_value(self) -> str | None:
        cmap = self._cmap
        if cmap is None:
            return None
        return cmap.get("ike_state")


# ---------- Traffic counters & throughput ----------


class _CryptoMapBytesBase(_CryptoMapSensorBase):
    """Shared RX/TX byte counter base.

    The counters are a sum across all phase-2 SAs of the tunnel. A
    phase-2 rekey resets each SA's counter to zero, which is handled
    by ``SensorStateClass.TOTAL_INCREASING`` — HA Statistics treats a
    drop as a reset rather than a negative delta.
    """

    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = UnitOfInformation.BYTES
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _field = "rx_bytes"

    @property
    def native_value(self) -> int | None:
        cmap = self._cmap
        if cmap is None:
            return None
        v = cmap.get(self._field)
        if v is None:
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            return None


class KeeneticCryptoMapRxBytesSensor(_CryptoMapBytesBase):
    _attr_icon = "mdi:download"
    _field = "rx_bytes"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_cmap_{self._cmap_name}_rx_bytes"

    @property
    def name(self) -> str:
        return "RX Bytes"


class KeeneticCryptoMapTxBytesSensor(_CryptoMapBytesBase):
    _attr_icon = "mdi:upload"
    _field = "tx_bytes"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_cmap_{self._cmap_name}_tx_bytes"

    @property
    def name(self) -> str:
        return "TX Bytes"


class _CryptoMapThroughputBase(_CryptoMapSensorBase):
    """Shared RX/TX throughput base.

    Throughput is computed in the coordinator as a delta against the
    previous tick, with a clamp at zero to absorb counter resets on
    phase-2 rekey.
    """

    _attr_device_class = SensorDeviceClass.DATA_RATE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = UnitOfDataRate.BYTES_PER_SECOND
    _attr_suggested_display_precision = 0
    _field = "rx_throughput"

    @property
    def native_value(self) -> float | None:
        cmap = self._cmap
        if cmap is None:
            return None
        v = cmap.get(self._field)
        if v is None:
            return None
        try:
            return float(v)
        except (TypeError, ValueError):
            return None


class KeeneticCryptoMapRxThroughputSensor(_CryptoMapThroughputBase):
    _attr_icon = "mdi:download-network"
    _field = "rx_throughput"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_cmap_{self._cmap_name}_rx_throughput"

    @property
    def name(self) -> str:
        return "RX Throughput"


class KeeneticCryptoMapTxThroughputSensor(_CryptoMapThroughputBase):
    _attr_icon = "mdi:upload-network"
    _field = "tx_throughput"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_cmap_{self._cmap_name}_tx_throughput"

    @property
    def name(self) -> str:
        return "TX Throughput"
