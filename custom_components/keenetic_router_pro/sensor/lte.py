"""LTE / cellular sensors for Keenetic Router Pro — issue #47.

Two distinct sensor families share this module:

1. **Data-usage sensors** (the primary issue #47 ask). Source: the
   ``show interface traffic-counter`` endpoint, which mirrors the
   "Data Usage & Limit" page in the Keenetic web UI. Five sensors
   per LTE interface plus two binary alarms: used / remaining /
   limit / threshold / days-until-reset / quota %, plus
   limit-exceeded and threshold-exceeded binary sensors.

2. **LTE diagnostics** (bonus telemetry). Source: the flat top-level
   fields on the LTE interface payload itself. Operator, technology,
   signal-level bars, RSSI / RSRP / RSRQ / CINR, band, roaming flag,
   modem temperature, connection state. These existed in an earlier
   sprint with the wrong field paths (assumed ``raw.mobile.*`` nesting
   that some firmwares use, but not the maintainer's UsbLte0 on
   Marvell-based hardware); this implementation reads the flat layout
   that real firmware actually returns.

Both families attach to the existing per-WAN sub-device that the
generic WAN sensors already populate — so a user with a 4G uplink
sees one device card with throughput, byte counters, signal quality
and quota usage all together, not two scattered devices.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    EntityCategory,
    SIGNAL_STRENGTH_DECIBELS,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    UnitOfFrequency,
    UnitOfInformation,
    UnitOfTemperature,
    UnitOfTime,
    PERCENTAGE,
)

from ..coordinator import KeeneticCoordinator
from ..entity import WanEntity
from ..utils import safe_float, safe_int

_LOGGER = logging.getLogger(__name__)


def is_lte_wan(wan: dict[str, Any] | None) -> bool:
    """Return True if a WAN dict represents a cellular / LTE modem.

    Uses the trait list as primary signal because Keenetic traits are
    stable across firmware versions. Falls back to type-name matching
    and id-prefix tokens for older firmwares that don't populate
    traits, and to the presence of a ``mobile.*`` sub-dict (used by
    nested-format firmware variants) as a last resort.
    """
    if not isinstance(wan, dict):
        return False
    raw = wan.get("raw") if isinstance(wan.get("raw"), dict) else {}
    iface_id = str(wan.get("id") or "").lower()
    iface_type = str(wan.get("type") or raw.get("type") or "").lower()
    traits = raw.get("traits") or wan.get("traits") or []
    if isinstance(traits, list) and (
        "UsbLte" in traits or "Mobile" in traits
    ):
        return True
    if iface_type in ("usblte", "usbmodem", "usbqmi", "usbmodemcdc"):
        return True
    if any(tok in iface_id for tok in ("usblte", "usbmodem", "usbqmi")):
        return True
    if any(tok in iface_type for tok in ("mobile", "lte", "3g", "4g", "5g")):
        return True
    # Some firmwares group mobile fields under raw.mobile.*; presence
    # of that sub-dict is a strong "is cellular" signal.
    if isinstance(raw.get("mobile"), dict):
        return True
    return False


# ---------------------------------------------------------------------------
# Shared base
# ---------------------------------------------------------------------------


class _LteSensorBase(WanEntity, SensorEntity):
    """Base for cellular sensors that read from coordinator data only.

    All LTE-family sensors are gated on the same "available" condition
    — if the coordinator doesn't have a WAN entry for our interface
    they all go to "unavailable" together, rather than each one
    independently rendering as 'Unknown'.
    """

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        wan_id: str,
    ) -> None:
        WanEntity.__init__(
            self, coordinator, entry.entry_id, entry.title, wan_id
        )

    @property
    def _raw(self) -> dict[str, Any]:
        """Flat top-level interface payload from ``show interface``."""
        wan = self._wan
        if not wan:
            return {}
        raw = wan.get("raw")
        return raw if isinstance(raw, dict) else {}

    @property
    def _mobile_sub(self) -> dict[str, Any]:
        """``raw.mobile.*`` sub-dict (for firmwares using nested layout).

        Several Keenetic firmware revisions place LTE telemetry under
        a ``mobile`` sub-key; others (e.g. UsbLte0 / Marvell-based
        modems verified by the maintainer) keep everything flat on
        the top-level interface payload. Sensors below check both
        layouts: flat first (more common on cellular-only modems),
        then the nested fallback.
        """
        m = self._raw.get("mobile")
        return m if isinstance(m, dict) else {}

    @property
    def _usage(self) -> dict[str, Any]:
        """Per-interface traffic-counter dict from the coordinator."""
        data = self.coordinator.data or {}
        usage_map = data.get("lte_data_usage") or {}
        return usage_map.get(self._wan_id, {}) if isinstance(usage_map, dict) else {}

    @property
    def available(self) -> bool:
        return self._wan is not None


# ---------------------------------------------------------------------------
# Data-usage sensors (issue #47 primary)
# ---------------------------------------------------------------------------


class _LteDataUsageSensorBase(_LteSensorBase):
    """Data-usage sensors read unknown — not unavailable — with the counter off.

    Leaving the router's traffic counter disabled, or never configuring
    a quota at all, is a perfectly valid setup rather than a broken
    data source. Marking the entities "unavailable" for it (as this
    class used to) left six permanently-red rows on the dashboard of
    every user without a quota, which is what issue #63 reported.

    Blanking the usage dict instead makes each ``native_value`` return
    ``None``, so the entities stay visible as "unknown" while still
    keeping zeros out of long-term statistics — the statistics
    compiler ignores non-numeric states, which was the original reason
    for hiding them. Stale counter values are not reported either,
    since they'd be indistinguishable from live ones.
    """

    @property
    def _usage(self) -> dict[str, Any]:
        usage = super()._usage
        if not usage or not usage.get("enabled", False):
            return {}
        return usage

    @property
    def _fingerprint_source(self) -> dict[str, Any] | None:
        """Include the quota dict, which is where our value lives.

        The inherited fingerprint only covers the ``wan_interfaces``
        row, but these sensors read ``lte_data_usage``. If the WAN row
        happens to sit still (an idle or down interface), the dedup in
        _FingerprintedCoordinatorEntity would skip the state write and
        the counter turning on — or usage ticking up — would never
        reach HA.
        """
        wan = self._wan
        if wan is None:
            return None
        return {**wan, "_lte_usage": super()._usage}

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Explain an "unknown" reading rather than leaving it bare."""
        raw = super()._usage
        if not raw:
            return None
        return {
            "counter_enabled": raw.get("enabled"),
            "raw_unit": raw.get("raw_unit"),
            "last_saved": raw.get("last_saved"),
        }


class KeeneticLteDataUsedSensor(_LteDataUsageSensorBase):
    """Current month-to-date data usage in GB."""
    _attr_icon = "mdi:download-network"
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_suggested_display_precision = 2

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_data_used"

    @property
    def name(self) -> str:
        return "Data Used"

    @property
    def native_value(self) -> float | None:
        return self._usage.get("used_gb")


class KeeneticLteDataRemainingSensor(_LteDataUsageSensorBase):
    """Remaining data in GB until the monthly quota is reached."""
    _attr_icon = "mdi:gauge"
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision = 2

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_data_remaining"

    @property
    def name(self) -> str:
        return "Data Remaining"

    @property
    def native_value(self) -> float | None:
        return self._usage.get("remaining_gb")


class KeeneticLteDataLimitSensor(_LteDataUsageSensorBase):
    """Configured monthly data limit in GB (diagnostic)."""
    _attr_icon = "mdi:database-arrow-up"
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_suggested_display_precision = 2

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_data_limit"

    @property
    def name(self) -> str:
        return "Data Limit"

    @property
    def native_value(self) -> float | None:
        return self._usage.get("limit_gb")


class KeeneticLteDataThresholdSensor(_LteDataUsageSensorBase):
    """Warning threshold in GB (diagnostic)."""
    _attr_icon = "mdi:alert-circle-outline"
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_suggested_display_precision = 2

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_data_threshold"

    @property
    def name(self) -> str:
        return "Data Threshold"

    @property
    def native_value(self) -> float | None:
        return self._usage.get("threshold_gb")


class KeeneticLteDaysUntilResetSensor(_LteDataUsageSensorBase):
    """Days remaining until the monthly counter resets."""
    _attr_icon = "mdi:calendar-clock"
    _attr_native_unit_of_measurement = UnitOfTime.DAYS
    _attr_state_class = SensorStateClass.MEASUREMENT

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_days_until_reset"

    @property
    def name(self) -> str:
        return "Days Until Reset"

    @property
    def native_value(self) -> int | None:
        return self._usage.get("days_left")


class KeeneticLteQuotaUsageSensor(_LteDataUsageSensorBase):
    """Current quota usage as a percentage of the configured limit.

    Computed locally rather than from the router because the router's
    "threshold" value is itself a percentage of the limit (e.g. 90 %)
    — the router never reports "current % of limit", just the absolute
    value-in-GB pair. Local computation also means the percentage
    updates the moment ``used_gb`` ticks, even between coordinator
    refreshes that miss a counter-save event.
    """
    _attr_icon = "mdi:percent"
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision = 1

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_quota_usage"

    @property
    def name(self) -> str:
        return "Quota Usage"

    @property
    def native_value(self) -> float | None:
        usage = self._usage
        used = usage.get("used_gb")
        limit = usage.get("limit_gb")
        if used is None or limit is None or limit <= 0:
            return None
        pct = (used / limit) * 100.0
        # Defensive clamp: routers occasionally over-report by a sliver
        # past 100 % between threshold-trigger and counter-reset, but
        # values like 250 % would just look broken.
        return max(0.0, min(pct, 999.0))


# ---------------------------------------------------------------------------
# LTE telemetry sensors (bonus diagnostics)
# ---------------------------------------------------------------------------


def _flat_or_nested(raw: dict[str, Any], mobile: dict[str, Any], *keys: str) -> Any:
    """Find a value by trying it at the flat root first, then under mobile.*.

    Both layouts are seen in the wild; we want every sensor to work on
    both without each one duplicating the fallback chain inline.
    """
    for k in keys:
        if k in raw and raw[k] not in (None, ""):
            return raw[k]
    for k in keys:
        if k in mobile and mobile[k] not in (None, ""):
            return mobile[k]
    return None


class KeeneticLteOperatorSensor(_LteSensorBase):
    """Mobile network operator name (e.g. ``Avea``)."""
    _attr_icon = "mdi:cellphone-cog"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_operator"

    @property
    def name(self) -> str:
        return "LTE Operator"

    @property
    def native_value(self) -> str | None:
        v = _flat_or_nested(
            self._raw, self._mobile_sub,
            "operator", "provider", "plmn-description",
        )
        return str(v) if v is not None else None


class KeeneticLteTechnologySensor(_LteSensorBase):
    """Access technology in use (``4G`` / ``5G`` / ``3G`` / ``2G``).

    On firmwares using the flat layout the ``mobile`` key on the
    interface payload is *itself* a string with the technology name
    (verified against UsbLte0 returning ``mobile: "4G"``). On nested
    layouts the equivalent value lives at ``mobile.access-technology``.
    We accept both.
    """
    _attr_icon = "mdi:signal-cellular-3"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_technology"

    @property
    def name(self) -> str:
        return "LTE Technology"

    @property
    def native_value(self) -> str | None:
        # Flat: raw.mobile is a string ("4G"). Nested: raw.mobile is a
        # dict, so check nested keys instead.
        flat_mobile = self._raw.get("mobile")
        if isinstance(flat_mobile, str) and flat_mobile.strip():
            return flat_mobile
        v = _flat_or_nested(
            self._raw, self._mobile_sub,
            "access-technology", "technology", "mode", "network-type",
        )
        return str(v) if v is not None else None


class KeeneticLteSignalLevelSensor(_LteSensorBase):
    """Signal bars (0-5). Driven by the modem's own bucketing."""
    _attr_icon = "mdi:signal"
    _attr_state_class = SensorStateClass.MEASUREMENT

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_signal_level"

    @property
    def name(self) -> str:
        return "LTE Signal Level"

    @property
    def native_value(self) -> int | None:
        v = _flat_or_nested(self._raw, self._mobile_sub, "signal-level")
        return safe_int(v)


class KeeneticLteRssiSensor(_LteSensorBase):
    """Raw signal strength (RSSI). Negative dBm; closer to 0 is better."""
    _attr_icon = "mdi:wifi-strength-2"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS_MILLIWATT
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_rssi"

    @property
    def name(self) -> str:
        return "LTE RSSI"

    @property
    def native_value(self) -> int | None:
        v = _flat_or_nested(self._raw, self._mobile_sub, "rssi", "signal")
        return safe_int(v)


class KeeneticLteRsrpSensor(_LteSensorBase):
    """Reference Signal Received Power. -80 great, -110 poor."""
    _attr_icon = "mdi:signal-cellular-outline"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS_MILLIWATT
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_rsrp"

    @property
    def name(self) -> str:
        return "LTE RSRP"

    @property
    def native_value(self) -> int | None:
        v = _flat_or_nested(self._raw, self._mobile_sub, "rsrp")
        return safe_int(v)


class KeeneticLteRsrqSensor(_LteSensorBase):
    """Reference Signal Received Quality (dB ratio).

    No SIGNAL_STRENGTH device_class because RSRQ is a ratio in dB,
    not absolute power in dBm.
    """
    _attr_icon = "mdi:signal-cellular-2"
    _attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_rsrq"

    @property
    def name(self) -> str:
        return "LTE RSRQ"

    @property
    def native_value(self) -> int | None:
        v = _flat_or_nested(self._raw, self._mobile_sub, "rsrq")
        return safe_int(v)


class KeeneticLteCinrSensor(_LteSensorBase):
    """Carrier-to-Interference-plus-Noise Ratio (dB).

    Some firmwares expose this as ``sinr`` (the more common acronym);
    Marvell-based Keenetic LTE modems report it as ``cinr``. We accept
    either field name.
    """
    _attr_icon = "mdi:signal-cellular-1"
    _attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_cinr"

    @property
    def name(self) -> str:
        return "LTE CINR"

    @property
    def native_value(self) -> int | None:
        v = _flat_or_nested(self._raw, self._mobile_sub, "cinr", "sinr", "snr")
        return safe_int(v)


class KeeneticLteBandSensor(_LteSensorBase):
    """Current LTE/5G band (e.g. ``1``, ``B7``)."""
    _attr_icon = "mdi:radio-tower"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_band"

    @property
    def name(self) -> str:
        return "LTE Band"

    @property
    def native_value(self) -> str | None:
        v = _flat_or_nested(
            self._raw, self._mobile_sub,
            "band", "current-band", "active-band",
        )
        return str(v) if v is not None else None


class KeeneticLteRoamingSensor(_LteSensorBase):
    """Whether the SIM is currently roaming (text yes/no for visibility)."""
    _attr_icon = "mdi:airplane"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_roaming"

    @property
    def name(self) -> str:
        return "LTE Roaming"

    @property
    def native_value(self) -> str | None:
        v = _flat_or_nested(self._raw, self._mobile_sub, "roaming")
        if v is None:
            return None
        # Surface as text rather than bool — HA renders the latter as
        # On/Off via switches, but this is a sensor (read-only fact).
        return "yes" if bool(v) else "no"


class KeeneticLteTemperatureSensor(_LteSensorBase):
    """Modem temperature in Celsius (diagnostic)."""
    _attr_icon = "mdi:thermometer"
    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_temperature"

    @property
    def name(self) -> str:
        return "LTE Modem Temperature"

    @property
    def native_value(self) -> float | None:
        v = _flat_or_nested(self._raw, self._mobile_sub, "temperature")
        return safe_float(v)


class KeeneticLteConnectionStateSensor(_LteSensorBase):
    """Modem connection state (e.g. ``Connected``, ``Registered``)."""
    _attr_icon = "mdi:cellphone-link"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_connection_state"

    @property
    def name(self) -> str:
        return "LTE Connection State"

    @property
    def native_value(self) -> str | None:
        v = _flat_or_nested(
            self._raw, self._mobile_sub,
            "connection-state", "registration", "status", "network-status",
        )
        return str(v) if v is not None else None


class KeeneticLteApnSensor(_LteSensorBase):
    """Configured APN (e.g. ``internet``)."""
    _attr_icon = "mdi:earth"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False  # niche, opt-in

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_apn"

    @property
    def name(self) -> str:
        return "LTE APN"

    @property
    def native_value(self) -> str | None:
        v = _flat_or_nested(self._raw, self._mobile_sub, "apn")
        if isinstance(v, dict):
            v = v.get("apn") or v.get("name")
        return str(v) if v else None


# ---------------------------------------------------------------------------
# Carrier aggregation + serving cell (issue #63)
# ---------------------------------------------------------------------------
#
# The whole CA block already reaches the coordinator untouched: api.py
# stores the complete `show interface` payload under wan["raw"], and
# only the top-level (primary) band was ever read. So a B20 + B3 link
# showed a plain "B20" and the only hint that aggregation was running
# was LTE Technology flipping between 4G and 4G+. Everything below is
# derived from data already in memory — no extra router request.

_INACTIVE_TOKENS = ("false", "no", "0", "off", "down", "")


def _band_label(value: Any) -> str | None:
    """Normalise a band field into a display label (``20`` -> ``B20``).

    Firmware reports LTE bands as bare numeric strings and 5G NR bands
    as ``n78``-style tokens; only the former get the ``B`` prefix.
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    if s.isdigit():
        return f"B{s}"
    if len(s) > 1 and s[0] in "bB" and s[1:].isdigit():
        return f"B{s[1:]}"
    return s


def _mhz(value: Any) -> float | None:
    """Parse a bandwidth field into MHz.

    ``bandwidth`` arrives as a string on the reporter's firmware
    ("10"), as an int on others, and occasionally with a unit suffix
    ("10 MHz") that ``safe_float`` rejects — fall back to the leading
    number in that case.
    """
    if value is None:
        return None
    f = safe_float(value)
    if f is not None:
        return f
    m = re.match(r"\s*(\d+(?:\.\d+)?)", str(value))
    return safe_float(m.group(1)) if m else None


def _carrier_is_active(entry: dict[str, Any]) -> bool:
    """Whether a carrier slot is actually carrying traffic.

    ``active`` is a bool on the reporter's firmware but may be a
    string elsewhere. Absent means "this firmware doesn't flag
    carriers" — treated as active, otherwise a whole CA block would
    silently vanish.
    """
    active = entry.get("active", True)
    if active is None:
        # Key present but JSON null — same meaning as absent. Without
        # this, bool(None) would drop every carrier and the whole CA
        # block would silently collapse to the single-carrier fallback.
        return True
    if isinstance(active, str):
        return active.strip().lower() not in _INACTIVE_TOKENS
    return bool(active)


def _carrier_sort_key(key: Any) -> tuple[int, int, str]:
    """Sort ``carrier`` keys numerically so the PCC ("1") stays first.

    The block is a dict keyed by index *as a string*, not a list, so a
    plain ``sorted()`` would put "10" before "2".
    """
    try:
        return (0, int(str(key)), "")
    except (TypeError, ValueError):
        return (1, 0, str(key))


def _parse_carriers(
    raw: dict[str, Any], mobile: dict[str, Any]
) -> list[dict[str, Any]]:
    """Normalise the CA block into an ordered list of active carriers.

    Payload shape (Hero 4G+ / Quectel EG060V, issue #63)::

        "band": "20", "bandwidth": "10",
        "carrier": {
          "1": {"active": true, "band": "20", "bandwidth": "10", "earfcn": 6200},
          "2": {"active": true, "band": "3",  "bandwidth": "15", "earfcn": 1875}
        }

    Firmwares without a ``carrier`` block still report the serving
    cell's ``band``/``bandwidth`` at the top level, so a single-carrier
    list is synthesised from those — the sensors then read "B20 / 1 /
    10 MHz" on non-CA hardware instead of going unknown.
    """
    block = raw.get("carrier")
    if not isinstance(block, dict):
        block = mobile.get("carrier")

    carriers: list[dict[str, Any]] = []
    if isinstance(block, dict):
        for key in sorted(block.keys(), key=_carrier_sort_key):
            entry = block.get(key)
            if not isinstance(entry, dict) or not _carrier_is_active(entry):
                continue
            band = _band_label(entry.get("band"))
            bandwidth = _mhz(entry.get("bandwidth"))
            earfcn = safe_int(entry.get("earfcn"))
            if band is None and bandwidth is None and earfcn is None:
                continue  # empty slot placeholder
            cinr = entry.get("cinr")
            if cinr is None:
                cinr = entry.get("sinr")
            carriers.append({
                "index": safe_int(key),
                # First surviving entry is the primary component
                # carrier; the rest are secondaries in index order.
                "role": "PCC" if not carriers else f"SCC{len(carriers)}",
                "band": band,
                "bandwidth_mhz": bandwidth,
                "earfcn": earfcn,
                "phy_cell_id": safe_int(entry.get("phy-cell-id")),
                "rsrp": safe_int(entry.get("rsrp")),
                "rsrq": safe_int(entry.get("rsrq")),
                "rssi": safe_int(entry.get("rssi")),
                "cinr": safe_int(cinr),
            })

    if carriers:
        return carriers

    band = _band_label(
        _flat_or_nested(raw, mobile, "band", "current-band", "active-band")
    )
    bandwidth = _mhz(_flat_or_nested(raw, mobile, "bandwidth"))
    earfcn = safe_int(_flat_or_nested(raw, mobile, "earfcn"))
    if band is None and bandwidth is None and earfcn is None:
        return []
    return [{
        "index": 1,
        "role": "PCC",
        "band": band,
        "bandwidth_mhz": bandwidth,
        "earfcn": earfcn,
        "phy_cell_id": safe_int(_flat_or_nested(raw, mobile, "phy-cell-id")),
        "rsrp": safe_int(_flat_or_nested(raw, mobile, "rsrp")),
        "rsrq": safe_int(_flat_or_nested(raw, mobile, "rsrq")),
        "rssi": safe_int(_flat_or_nested(raw, mobile, "rssi", "signal")),
        "cinr": safe_int(_flat_or_nested(raw, mobile, "cinr", "sinr", "snr")),
    }]


class _LteCarrierBase(_LteSensorBase):
    """Shared carrier parsing for the three aggregation sensors."""

    @property
    def _carriers(self) -> list[dict[str, Any]]:
        return _parse_carriers(self._raw, self._mobile_sub)


class KeeneticLteCarrierAggregationSensor(_LteCarrierBase):
    """Active carrier set as one label — e.g. ``B20 + B3``.

    Sibling of ``LTE Band``: that one keeps reporting the primary
    carrier only, so existing dashboards and automations are
    unaffected; this one describes the whole aggregated link.
    Per-carrier detail lives in attributes rather than in a dozen
    extra entities.
    """
    _attr_icon = "mdi:antenna"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    # The carrier list churns on every handover; keeping it out of the
    # recorder avoids bloating attribute history for no benefit.
    _unrecorded_attributes = frozenset({"carriers"})

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_carrier_aggregation"

    @property
    def name(self) -> str:
        return "LTE Carrier Aggregation"

    @property
    def native_value(self) -> str | None:
        labels = [c["band"] for c in self._carriers if c.get("band")]
        if not labels:
            return None
        # HA caps state strings at 255 chars; 5-carrier CA is ~30.
        return " + ".join(labels)[:255]

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        carriers = self._carriers
        if not carriers:
            return None
        widths = [
            c["bandwidth_mhz"] for c in carriers
            if c.get("bandwidth_mhz") is not None
        ]
        return {
            "carriers": carriers,
            "carrier_count": len(carriers),
            "aggregated_bandwidth_mhz": round(sum(widths), 1) if widths else None,
            "primary_band": carriers[0].get("band"),
            "aggregated": len(carriers) > 1,
        }


class KeeneticLteCarrierCountSensor(_LteCarrierBase):
    """Number of active component carriers (1 = no aggregation)."""
    _attr_icon = "mdi:antenna"
    _attr_state_class = SensorStateClass.MEASUREMENT

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_carrier_count"

    @property
    def name(self) -> str:
        return "LTE Carriers"

    @property
    def native_value(self) -> int | None:
        # 0 means "no carrier data at all" -> unknown, not a real zero.
        return len(self._carriers) or None


class KeeneticLteAggregatedBandwidthSensor(_LteCarrierBase):
    """Sum of the active carriers' channel bandwidths, in MHz.

    Deliberately has no ``device_class``: HA's FREQUENCY class would
    offer MHz-to-GHz conversion and imply a carrier frequency, but
    this is a channel width — the raw MHz number is the meaningful one.
    """
    _attr_icon = "mdi:arrow-expand-horizontal"
    _attr_native_unit_of_measurement = UnitOfFrequency.MEGAHERTZ
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision = 0

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_aggregated_bandwidth"

    @property
    def name(self) -> str:
        return "LTE Aggregated Bandwidth"

    @property
    def native_value(self) -> float | None:
        widths = [
            c["bandwidth_mhz"] for c in self._carriers
            if c.get("bandwidth_mhz") is not None
        ]
        if not widths:
            return None
        return round(sum(widths), 1)


class KeeneticLteCellSensor(_LteCarrierBase):
    """Serving cell identity, as one state plus the details in attributes.

    eNB id, sector, TAC, physical cell id and EARFCN all change
    together at handover, so five separate entities would just mean
    five simultaneous state writes saying the same thing. One entity
    whose state changes exactly when the cell changes is what an
    automation ("notify me when the antenna re-points") actually wants.

    Field names vary between firmwares, hence the candidate lists.
    """
    _attr_icon = "mdi:radio-tower"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_lte_cell"

    @property
    def name(self) -> str:
        return "LTE Serving Cell"

    def _field(self, *keys: str) -> Any:
        return _flat_or_nested(self._raw, self._mobile_sub, *keys)

    @property
    def _pcc(self) -> dict[str, Any]:
        """Primary component carrier, or an empty dict.

        On the firmware in issue #63 ``earfcn`` and ``phy-cell-id`` live
        inside ``carrier["1"]`` rather than at the top level, so cell
        identity has to fall back to the PCC or this sensor would sit
        at "unknown" on exactly the hardware that asked for it.
        """
        carriers = self._carriers
        return carriers[0] if carriers else {}

    @property
    def native_value(self) -> str | None:
        enb = safe_int(self._field("enb-id", "enbid", "enb_id"))
        sector = safe_int(self._field("sector-id", "sectorid", "sector_id"))
        if enb is not None and sector is not None:
            return f"{enb}-{sector}"
        cell = self._field("cell-id", "cellid", "cell_id", "ci")
        if cell is not None:
            return str(cell)
        pci = safe_int(self._field("phy-cell-id", "pci", "phy_cell_id"))
        if pci is None:
            pci = self._pcc.get("phy_cell_id")
        if pci is not None:
            return str(pci)
        earfcn = safe_int(self._field("earfcn", "dl-earfcn"))
        if earfcn is None:
            earfcn = self._pcc.get("earfcn")
        return f"EARFCN {earfcn}" if earfcn is not None else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        attrs = {
            "enb_id": safe_int(self._field("enb-id", "enbid", "enb_id")),
            "sector_id": safe_int(
                self._field("sector-id", "sectorid", "sector_id")
            ),
            "cell_id": self._field("cell-id", "cellid", "cell_id", "ci"),
            "tac": self._field("tac", "tracking-area-code"),
            "phy_cell_id": safe_int(
                self._field("phy-cell-id", "pci", "phy_cell_id")
            ) or self._pcc.get("phy_cell_id"),
            "earfcn": safe_int(self._field("earfcn", "dl-earfcn"))
            or self._pcc.get("earfcn"),
            "modem_model": self._field("model", "modem-model"),
            "modem_firmware": self._field("revision", "firmware", "modem-revision"),
            # IMEI is deliberately not exposed: it uniquely identifies
            # the subscriber's hardware and would leak through
            # screenshots and shared attribute dumps, which the rest of
            # the integration takes care to avoid (see SECURITY.md).
        }
        # Drop the keys this firmware doesn't report rather than
        # showing a card full of "None".
        cleaned = {k: v for k, v in attrs.items() if v is not None}
        return cleaned or None
