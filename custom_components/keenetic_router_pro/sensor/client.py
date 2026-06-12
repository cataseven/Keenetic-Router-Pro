"""Client sensors for tracked devices."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfInformation, UnitOfTime, PERCENTAGE, EntityCategory

from ..coordinator import KeeneticCoordinator
from ..entity import ClientEntity
from ..const import DOMAIN
from ..utils import safe_float, safe_int
from .monotonic import MonotonicUptimeMixin


class KeeneticClientIpSensor(ClientEntity, SensorEntity):
    """IP address sensor for client."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:ip-network"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
        initial_ip: str | None = None,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label, initial_ip)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_ip"

    @property
    def name(self) -> str:
        return "IP"

    @property
    def native_value(self) -> str | None:
        return self.ip_address


class KeeneticClientRegisteredSensor(ClientEntity, SensorEntity):
    """Registered status sensor (DHCP reservation)."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:bookmark-check"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_registered"

    @property
    def name(self) -> str:
        return "DHCP Registered"

    @property
    def native_value(self) -> str:
        client = self._client
        if client:
            return "yes" if client.get("registered", False) else "no"
        return "unknown"

    @property
    def icon(self) -> str:
        client = self._client
        if client and client.get("registered", False):
            return "mdi:bookmark-check"
        return "mdi:bookmark-outline"


class KeeneticClientLinkSensor(ClientEntity, SensorEntity):
    """Link status sensor (up/down)."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:ethernet"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_link"

    @property
    def name(self) -> str:
        return "Link Status"

    @property
    def native_value(self) -> str:
        client = self._client
        if client:
            return client.get("link", "down")
        return "unknown"

    @property
    def icon(self) -> str:
        status = self.native_value
        if status == "up":
            return "mdi:link"
        return "mdi:link-off"


class KeeneticClientUptimeSensor(ClientEntity, MonotonicUptimeMixin, SensorEntity):
    """Uptime sensor for client."""
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_has_entity_name = True
    _attr_icon = "mdi:timer-outline"
    _attr_device_class = SensorDeviceClass.DURATION
    # TOTAL_INCREASING: client Wi-Fi session uptime resets on re-association,
    # matches the router/mesh/PPPoE/WireGuard rationale.
    #
    # Issue #60: the router sometimes reports a slightly *lower* uptime
    # (a few % — e.g. roaming between mesh members or a power-save
    # blip re-basing the session counter) which lands in the recorder's
    # "not strictly increasing" warning band. MonotonicUptimeMixin
    # holds the high-water mark across such dips and passes genuine
    # re-association resets (drops below 90%) through untouched.
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_suggested_display_precision = 0
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_uptime"

    @property
    def name(self) -> str:
        return "Uptime"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfTime.SECONDS

    @property
    def native_value(self) -> int | None:
        client = self._client
        if client:
            uptime = client.get("uptime")
            if uptime not in (None, "", "unknown", "Unknown"):
                return self._clamp_monotonic(safe_int(uptime))
        return None


class KeeneticClientFirstSeenSensor(ClientEntity, SensorEntity):
    """First seen timestamp sensor."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:calendar-clock"
    _attr_device_class = SensorDeviceClass.DURATION
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_first_seen"

    @property
    def name(self) -> str:
        return "First Seen"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfTime.SECONDS

    @property
    def native_value(self) -> int:
        client = self._client
        if not client:
            return None
        first_seen = client.get("first-seen")
        if first_seen in (None, "", "unknown", "Unknown"):
            return None
        return safe_int(first_seen)


class KeeneticClientLastSeenSensor(ClientEntity, SensorEntity):
    """Last seen seconds ago sensor."""
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_has_entity_name = True
    _attr_icon = "mdi:clock"
    _attr_device_class = SensorDeviceClass.DURATION
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_last_seen"

    @property
    def name(self) -> str:
        return "Last Seen"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfTime.SECONDS

    @property
    def native_value(self) -> int:
        client = self._client
        if not client:
            return None
        last_seen = client.get("last-seen")
        if last_seen in (None, "", "unknown", "Unknown"):
            return None
        return safe_int(last_seen)


class KeeneticClientRxSensor(ClientEntity, SensorEntity):
    """Received traffic sensor."""
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_has_entity_name = True
    _attr_icon = "mdi:download-network"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_rx"

    @property
    def name(self) -> str:
        return "RX"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfInformation.GIGABYTES

    @property
    def native_value(self) -> float | None:
        client = self._client
        if not client:
            return None
        bytes_val = safe_float(client.get("rxbytes", 0))
        if bytes_val is None:
            return None
        return round(bytes_val / (1024 ** 3), 2)


class KeeneticClientTxSensor(ClientEntity, SensorEntity):
    """Sent traffic sensor."""
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_has_entity_name = True
    _attr_icon = "mdi:upload-network"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_tx"

    @property
    def name(self) -> str:
        return "TX"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfInformation.GIGABYTES

    @property
    def native_value(self) -> float | None:
        client = self._client
        if not client:
            return None
        bytes_val = safe_float(client.get("txbytes", 0))
        if bytes_val is None:
            return None
        return round(bytes_val / (1024 ** 3), 2)


class KeeneticClientSpeedSensor(ClientEntity, SensorEntity):
    """Link speed sensor (Mbps)."""
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_has_entity_name = True
    _attr_icon = "mdi:speedometer"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_speed"

    @property
    def name(self) -> str:
        return "Link Speed"

    @property
    def native_unit_of_measurement(self) -> str:
        return "Mbps"

    @property
    def native_value(self) -> int | None:
        client = self._client
        if not client:
            return None
        return safe_int(client.get("speed"))


class KeeneticClientPortSensor(ClientEntity, SensorEntity):
    """Port number for wired connections."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:ethernet-cable"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_port"

    @property
    def name(self) -> str:
        return "Port"

    @property
    def native_value(self) -> str | None:
        client = self._client
        if client:
            port = client.get("port")
            if port is not None:
                return str(port)
        return None


class KeeneticClientRssiSensor(ClientEntity, SensorEntity):
    """WiFi RSSI (signal strength) sensor."""
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_has_entity_name = True
    _attr_icon = "mdi:wifi"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_rssi"

    @property
    def name(self) -> str:
        return "RSSI"

    @property
    def native_unit_of_measurement(self) -> str:
        return "dBm"

    @property
    def native_value(self) -> int | None:
        client = self._client
        if not client:
            return None
        return safe_int(client.get("rssi"))


class KeeneticClientTxRateSensor(ClientEntity, SensorEntity):
    """WiFi transmission rate sensor."""
    # Opt out of the base-class fingerprint dedup: this sensor's
    # native_value reads from a field that the parent entity's
    # _FINGERPRINT_IGNORE set marks as 'volatile / no state write'.
    # Without the override, the sensor would never tick.
    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _attr_has_entity_name = True
    _attr_icon = "mdi:transmission-tower"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_txrate"

    @property
    def name(self) -> str:
        return "TX Rate"

    @property
    def native_unit_of_measurement(self) -> str:
        return "Mbps"

    @property
    def native_value(self) -> int | None:
        client = self._client
        if not client:
            return None
        return safe_int(client.get("txrate"))
    
class KeeneticClientConnectionTypeSensor(ClientEntity, SensorEntity):
    """Connection type sensor (WiFi 2.4GHz, WiFi 5GHz, Ethernet)."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:connection"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_connection_type"

    @property
    def name(self) -> str:
        return "Connection Type"

    @property
    def native_value(self) -> str:
        """Return connection type."""
        client = self._client
        if not client:
            return "unknown"

        # Check if it's a wired connection (has port or speed without mws/ssid)
        if client.get("port") is not None or client.get("auto-negotiation") is not None:
            speed = client.get("speed")
            if speed:
                return f"Ethernet ({speed} Mbps)"
            return "Ethernet"

        # Check WiFi connection via mws (Mesh WiFi System)
        mws = client.get("mws")
        if mws:
            ap = mws.get("ap", "")
            if "WifiMaster0" in ap:
                return "WiFi 2.4 GHz (Mesh)"
            elif "WifiMaster1" in ap:
                return "WiFi 5 GHz (Mesh)"
            return f"WiFi (Mesh) - {ap}"

        # Check direct WiFi connection (via ssid/ap)
        ssid = client.get("ssid")
        ap = client.get("ap")
        
        if ssid or ap:
            # Determine band from AP name
            ap_name = str(ap) if ap else ""
            if "WifiMaster0" in ap_name:
                band = "2.4 GHz"
            elif "WifiMaster1" in ap_name:
                band = "5 GHz"
            else:
                # Try to determine from txrate/mode
                txrate = client.get("txrate", 0)
                mode = client.get("mode", "")
                if txrate > 300 or "ac" in mode or "ax" in mode:
                    band = "5 GHz"
                else:
                    band = "2.4 GHz"
            
            if ssid:
                return f"WiFi {band} - {ssid}"
            return f"WiFi {band}"

        # Try to determine from interface
        iface = client.get("interface")
        if iface:
            iface_name = iface if isinstance(iface, str) else iface.get("name", "")
            if "WifiMaster0" in iface_name:
                return "WiFi 2.4 GHz"
            elif "WifiMaster1" in iface_name:
                return "WiFi 5 GHz"
            elif "GigabitEthernet" in iface_name:
                return "Ethernet"

        # Try to determine from txrate/speed
        txrate = client.get("txrate")
        if txrate:
            if txrate > 300:
                return "WiFi 5 GHz (likely)"
            return "WiFi 2.4 GHz (likely)"

        return "unknown"

    @property
    def icon(self) -> str:
        """Return icon based on connection type."""
        conn_type = self.native_value
        if "Ethernet" in conn_type:
            return "mdi:ethernet"
        elif "2.4" in conn_type:
            return "mdi:wifi"
        elif "5" in conn_type:
            return "mdi:wifi-strength-4"
        else:
            return "mdi:wifi-question"

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return additional attributes."""
        client = self._client
        if not client:
            return None

        attrs: dict[str, Any] = {}

        # Add WiFi specific attributes
        mws = client.get("mws")
        if mws:
            attrs["ap"] = mws.get("ap")
            attrs["mode"] = mws.get("mode")
            attrs["ht"] = mws.get("ht")
            attrs["security"] = mws.get("security")
            attrs["authenticated"] = mws.get("authenticated")
            if mws.get("roam"):
                attrs["roaming"] = mws.get("roam")

        # Add direct WiFi attributes
        if client.get("ssid"):
            attrs["ssid"] = client.get("ssid")
        if client.get("ap"):
            attrs["ap"] = client.get("ap")
        if client.get("mode"):
            attrs["mode"] = client.get("mode")

        # Add Ethernet attributes
        if client.get("speed"):
            attrs["speed_mbps"] = client.get("speed")
        if client.get("duplex") is not None:
            attrs["duplex"] = "Full" if client.get("duplex") else "Half"
        if client.get("port"):
            attrs["port"] = client.get("port")

        return attrs if attrs else None


class KeeneticClientWifiBandSensor(ClientEntity, SensorEntity):
    """WiFi band sensor (2.4GHz, 5GHz, or None for wired)."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:wifi"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_wifi_band"

    @property
    def name(self) -> str:
        return "WiFi Band"

    @property
    def native_value(self) -> str | None:
        """Return WiFi band."""
        client = self._client
        if not client:
            return None

        # Check if wired
        if client.get("port") is not None or client.get("auto-negotiation") is not None:
            return None

        # Check via mws
        mws = client.get("mws")
        if mws:
            ap = mws.get("ap", "")
            if "WifiMaster0" in ap:
                return "2.4 GHz"
            elif "WifiMaster1" in ap:
                return "5 GHz"

        # Check via direct ap
        ap = client.get("ap", "")
        if "WifiMaster0" in ap:
            return "2.4 GHz"
        elif "WifiMaster1" in ap:
            return "5 GHz"

        # Try to determine from txrate
        txrate = client.get("txrate")
        if txrate:
            if txrate > 300:
                return "5 GHz"
            return "2.4 GHz"

        return None

    @property
    def icon(self) -> str:
        """Return icon based on band."""
        band = self.native_value
        if band == "5 GHz":
            return "mdi:wifi-strength-4"
        elif band == "2.4 GHz":
            return "mdi:wifi"
        else:
            return "mdi:wifi-off"


class KeeneticClientWifiModeSensor(ClientEntity, SensorEntity):
    """WiFi mode sensor (11n, 11ac, 11ax)."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:wifi-settings"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        mac: str,
        label: str,
    ) -> None:
        ClientEntity.__init__(self, coordinator, entry.entry_id, entry.title, mac, label)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_wifi_mode"

    @property
    def name(self) -> str:
        return "WiFi Mode"

    @property
    def native_value(self) -> str | None:
        """Return WiFi mode."""
        client = self._client
        if not client:
            return None

        # Check via mws
        mws = client.get("mws")
        if mws:
            mode = mws.get("mode")
            if mode:
                return mode.upper()

        # Check direct mode
        mode = client.get("mode")
        if mode:
            return mode.upper()

        return None

    @property
    def icon(self) -> str:
        """Return icon based on WiFi mode."""
        mode = self.native_value
        if mode == "11AX":
            return "mdi:wifi-strength-4"
        elif mode == "11AC":
            return "mdi:wifi-strength-3"
        elif mode == "11N":
            return "mdi:wifi-strength-2"
        elif mode == "11G":
            return "mdi:wifi-strength-1"
        elif mode == "11B":
            return "mdi:wifi-strength-1"
        return "mdi:wifi"