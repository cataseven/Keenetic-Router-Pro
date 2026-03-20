"""Sensors for Keenetic Router Pro."""
from __future__ import annotations
from typing import Any
from homeassistant.components.sensor import (
    SensorEntity,
    SensorDeviceClass,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    UnitOfInformation, 
    UnitOfTime, 
    PERCENTAGE,
    UnitOfTemperature,
    EntityCategory,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .const import DOMAIN, DATA_COORDINATOR, CONF_TRACKED_CLIENTS
from .coordinator import KeeneticCoordinator
from .entity import ControllerEntity, MeshEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic Router Pro sensors from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: KeeneticCoordinator = data[DATA_COORDINATOR]
    entities: list[SensorEntity] = []

    # Temel sistem sensörleri
    entities.append(KeeneticCpuLoadSensor(coordinator, entry))
    entities.append(KeeneticMemoryUsageSensor(coordinator, entry))
    entities.append(KeeneticUptimeSensor(coordinator, entry))
    entities.append(KeeneticWanStatusSensor(coordinator, entry))
    entities.append(KeeneticFirmwareVersionSensor(coordinator, entry))

    # Yeni sensörler
    entities.append(KeeneticWanIpSensor(coordinator, entry))
    entities.append(KeeneticConnectedClientsSensor(coordinator, entry))
    entities.append(KeeneticRouterClientsSensor(coordinator, entry))
    entities.append(KeeneticDisconnectedClientsSensor(coordinator, entry))
    entities.append(KeeneticExtenderCountSensor(coordinator, entry))
    entities.append(KeeneticPppoeUptimeSensor(coordinator, entry))
    entities.append(KeeneticActiveConnectionsSensor(coordinator, entry))

    entities.append(KeeneticWifi24TemperatureSensor(coordinator, entry))
    entities.append(KeeneticWifi5TemperatureSensor(coordinator, entry))

    # WiFi 2.4GHz
    entities.append(KeeneticWifi24RxSensor(coordinator, entry))
    entities.append(KeeneticWifi24TxSensor(coordinator, entry))
    
    # WiFi 5GHz
    entities.append(KeeneticWifi5RxSensor(coordinator, entry))
    entities.append(KeeneticWifi5TxSensor(coordinator, entry))
    
    # LAN
    entities.append(KeeneticLanRxSensor(coordinator, entry))
    entities.append(KeeneticLanTxSensor(coordinator, entry))
    
    # WAN
    entities.append(KeeneticWanRxSensor(coordinator, entry))
    entities.append(KeeneticWanTxSensor(coordinator, entry))

    mesh_nodes = coordinator.data.get("mesh_nodes", [])
    for node in mesh_nodes:
        node_cid = node.get("cid") or node.get("id")
        if node_cid:
            entities.append(KeeneticMeshUptimeSensor(coordinator, entry, node_cid))
            entities.append(KeeneticMeshClientsSensor(coordinator, entry, node_cid))
            entities.append(KeeneticMeshFirmwareVersionSensor(coordinator, entry, node_cid))

    # WireGuard profilleri için sensörler
    wg_profiles = coordinator.data.get("wireguard", {}).get("profiles", {})
    for name in wg_profiles:
        entities.append(KeeneticWgUptimeSensor(coordinator, entry, name))
        entities.append(KeeneticWgRxSensor(coordinator, entry, name))
        entities.append(KeeneticWgTxSensor(coordinator, entry, name))

    # USB depolama sensörleri (ana router)
    usb_devices = coordinator.data.get("usb_storage", [])
    for usb_dev in usb_devices:
        dev_id = usb_dev.get("id")
        if dev_id:
            entities.append(KeeneticUsbStorageSensor(coordinator, entry, dev_id))

    # Mesh node USB sensörleri
    mesh_usb_devices = coordinator.data.get("mesh_usb", [])
    for musb_dev in mesh_usb_devices:
        dev_id = musb_dev.get("id")
        if dev_id:
            entities.append(KeeneticMeshUsbStorageSensor(
                coordinator, entry, dev_id,
                mesh_node_name=musb_dev.get("mesh_node_name"),
                mesh_cid=musb_dev.get("mesh_cid"),
            ))

    async_add_entities(entities)


class KeeneticCpuLoadSensor(ControllerEntity, SensorEntity):
    """CPU yükü sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "cpu_load"

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_cpu_load"

    @property
    def name(self) -> str:
        return "CPU Load"

    @property
    def native_unit_of_measurement(self) -> str:
        return PERCENTAGE

    @property
    def native_value(self) -> float | None:
        sys = self.coordinator.data.get("system", {}) or {}
        for key in ("cpu_load", "cpuload", "cpu", "cpu-utilization"):
            if key in sys:
                return float(sys[key])
        return None

    @property
    def _system(self) -> dict[str, Any]:
        return self.coordinator.data.get("system", {}) or {}


class KeeneticMemoryUsageSensor(ControllerEntity, SensorEntity):
    """RAM kullanım yüzdesi sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "memory_usage"

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_mem_usage"

    @property
    def name(self) -> str:
        return "Memory Usage"

    @property
    def native_unit_of_measurement(self) -> str:
        return PERCENTAGE

    @property
    def native_value(self) -> float | None:
        sys = self.coordinator.data.get("system", {}) or {}
        mem = sys.get("memory") or sys.get("mem")
        memtotal = sys.get("memtotal")
        memfree = sys.get("memfree")

        if isinstance(mem, str) and "/" in mem:
            try:
                part_used, part_total = mem.split("/", 1)
                used = float(part_used)
                total = float(part_total)
                if total > 0:
                    return round(used * 100.0 / total, 1)
            except (ValueError, TypeError):
                pass

        if isinstance(memtotal, (int, float)) and isinstance(memfree, (int, float)) and memtotal > 0:
            used = memtotal - memfree
            return round(used * 100.0 / memtotal, 1)

        for key in ("mem_used_percent", "memory_usage", "memusage"):
            if key in sys:
                try:
                    return float(sys[key])
                except (TypeError, ValueError):
                    continue

        return None


class KeeneticUptimeSensor(ControllerEntity, SensorEntity):
    """Router uptime sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "uptime"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_uptime"

    @property
    def name(self) -> str:
        return "Uptime"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfTime.SECONDS

    @property
    def native_value(self) -> int:
        sys = self.coordinator.data.get("system", {}) or {}
        candidates = []

        for key in ("uptime", "uptime_sec", "uptime_seconds"):
            if key in sys:
                candidates.append(sys.get(key))

        nested = sys.get("system")
        if isinstance(nested, dict):
            for key in ("uptime", "uptime_sec", "uptime_seconds"):
                if key in nested:
                    candidates.append(nested.get(key))

        for value in candidates:
            if value in (None, "", "unknown", "Unknown"):
                continue
            try:
                return int(float(value))
            except (TypeError, ValueError):
                continue

        return 0


class KeeneticWanStatusSensor(ControllerEntity, SensorEntity):
    """WAN bağlantı durumu sensörü.

    Durum değerleri:
      - "connected" → link up VE IP mevcut (gerçek internet bağlantısı)
      - "link_up"   → link up AMA IP yok (ISP sorunu / DHCP bekleniyor)
      - "down"      → interface kapalı veya bulunamadı
    """
    _attr_has_entity_name = True
    _attr_translation_key = "wan_status"

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_status"

    @property
    def name(self) -> str:
        return "WAN Status"

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


class _BaseWgSensor(ControllerEntity, SensorEntity):
    """WireGuard ortak mantığı."""
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
    """WireGuard tünel uptime sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "wireguard_uptime"

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
    """WireGuard RX (alınan trafik) sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "wireguard_rx"

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
    """WireGuard TX (gönderilen trafik) sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "wireguard_tx"

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


class KeeneticWanIpSensor(ControllerEntity, SensorEntity):
    """WAN IP adresi sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "wan_ip"
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


class KeeneticPppoeUptimeSensor(ControllerEntity, SensorEntity):
    """PPPoE bağlantı uptime sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "pppoe_uptime"
    _attr_icon = "mdi:timer-outline"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_pppoe_uptime"

    @property
    def name(self) -> str:
        return "PPPoE Uptime"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfTime.SECONDS

    @property
    def native_value(self) -> int:
        wan = self.coordinator.data.get("wan_status", {})
        uptime = wan.get("uptime")
        if uptime in (None, "", "unknown", "Unknown"):
            return 0
        try:
            return int(float(uptime))
        except (TypeError, ValueError):
            return 0

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
    """Aktif bağlantı sayısı sensörü (conntotal - connfree)."""
    _attr_has_entity_name = True
    _attr_translation_key = "active_connections"
    _attr_icon = "mdi:connection"

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_active_connections"

    @property
    def name(self) -> str:
        return "Active Connections"

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


class KeeneticConnectedClientsSensor(ControllerEntity, SensorEntity):
    """Bağlı cihaz sayısı sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "connected_clients"
    _attr_icon = "mdi:devices"

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_connected_clients"

    @property
    def name(self) -> str:
        return "Connected Clients"

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
    """Ana router'a doğrudan bağlı cihaz sayısı sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "router_clients"
    _attr_icon = "mdi:devices"

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_router_clients"

    @property
    def name(self) -> str:
        return "Clients"

    @property
    def native_value(self) -> int:
        stats = self.coordinator.data.get("client_stats", {})
        total_connected = stats.get("connected", 0)

        # Mesh node'lara bağlı client sayısını çıkar
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
    """Bağlı olmayan (bilinen) cihaz sayısı sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "disconnected_clients"
    _attr_icon = "mdi:lan-disconnect"

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_disconnected_clients"

    @property
    def name(self) -> str:
        return "Disconnected Clients"

    @property
    def native_value(self) -> int:
        stats = self.coordinator.data.get("client_stats", {})
        return stats.get("disconnected", 0)


class KeeneticExtenderCountSensor(ControllerEntity, SensorEntity):
    """Mesh extender/repeater sayısı sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "extender_count"
    _attr_icon = "mdi:access-point-network"

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_extender_count"

    @property
    def name(self) -> str:
        return "Extenders"

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


class KeeneticUsbStorageSensor(ControllerEntity, SensorEntity):
    """USB depolama sensörü."""
    _attr_has_entity_name = True
    _attr_translation_key = "usb_storage"
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
            "port": device.get("port"),
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
    """USB depolama sensörü - Mesh node üzerindeki USB."""
    _attr_has_entity_name = True
    _attr_translation_key = "mesh_usb_storage"
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
        return f"{safe_cid}_usb_{safe_id}"

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


class KeeneticMeshUptimeSensor(MeshEntity, SensorEntity):
    """Mesh node uptime sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "mesh_uptime"
    _attr_icon = "mdi:timer-outline"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, node_cid: str) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_uptime"

    @property
    def name(self) -> str:
        return f"Uptime"

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
    _attr_state_class = "measurement"

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, node_cid: str) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_clients"

    @property
    def name(self) -> str:
        node = self._node
        if node:
            node_name = node.get("name") or node.get("mac") or self._node_cid
            return f"Mesh - {node_name} Clients"
        return f"Mesh - {self._node_cid} Clients"

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
    

class KeeneticWifi24TemperatureSensor(ControllerEntity, SensorEntity):
    """WiFi 2.4GHz radio temperature sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "wifi_24_temperature"
    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:thermometer"

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._band = "2.4GHz"
        self._interface_prefix = "WifiMaster0"  # Обычно 2.4GHz

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wifi_24_temperature"

    @property
    def name(self) -> str:
        return f"WiFi {self._band} Temperature"

    @property
    def native_value(self) -> float | None:
        interfaces = self.coordinator.data.get("interfaces", {}) or {}
        
        # Ищем интерфейс по префиксу
        for iface_id, iface_data in interfaces.items():
            if iface_id.startswith(self._interface_prefix) and isinstance(iface_data, dict):
                temp = iface_data.get("temperature")
                if temp is not None:
                    try:
                        return float(temp)
                    except (TypeError, ValueError):
                        continue
        
        return None

    @property
    def available(self) -> bool:
        return self.native_value is not None


class KeeneticWifi5TemperatureSensor(ControllerEntity, SensorEntity):
    """WiFi 5GHz radio temperature sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "wifi_5_temperature"
    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:thermometer"

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._band = "5GHz"
        self._interface_prefix = "WifiMaster1"  # Обычно 5GHz

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wifi_5_temperature"

    @property
    def name(self) -> str:
        return f"WiFi {self._band} Temperature"

    @property
    def native_value(self) -> float | None:
        interfaces = self.coordinator.data.get("interfaces", {}) or {}
        
        for iface_id, iface_data in interfaces.items():
            if iface_id.startswith(self._interface_prefix) and isinstance(iface_data, dict):
                temp = iface_data.get("temperature")
                if temp is not None:
                    try:
                        return float(temp)
                    except (TypeError, ValueError):
                        continue
        
        return None

    @property
    def available(self) -> bool:
        return self.native_value is not None
    

class KeeneticInterfaceRxSensor(ControllerEntity, SensorEntity):
    """Сенсор входящего трафика для конкретного интерфейса."""
    _attr_has_entity_name = True
    _attr_translation_key = "interface_rx"
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
    """Сенсор исходящего трафика для конкретного интерфейса."""
    _attr_has_entity_name = True
    _attr_translation_key = "interface_tx"
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


class KeeneticWifi24RxSensor(ControllerEntity, SensorEntity):
    """WiFi 2.4GHz RX sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "wifi_24_rx"
    _attr_icon = "mdi:download-network"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._iface_name = "WifiMaster0"
        self._band = "2.4GHz"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wifi_24_rx"

    @property
    def name(self) -> str:
        return f"WiFi {self._band} RX"

    @property
    def native_value(self) -> float | None:
        stats = self.coordinator.data.get("interface_stats", {})
        iface_stats = stats.get(self._iface_name, {})
        rxbytes = iface_stats.get("rxbytes", 0)
        if rxbytes:
            return round(float(rxbytes) / (1024 ** 3), 2)
        return 0.0


class KeeneticWifi24TxSensor(ControllerEntity, SensorEntity):
    """WiFi 2.4GHz TX sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "wifi_24_tx"
    _attr_icon = "mdi:upload-network"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._iface_name = "WifiMaster0"
        self._band = "2.4GHz"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wifi_24_tx"

    @property
    def name(self) -> str:
        return f"WiFi {self._band} TX"

    @property
    def native_value(self) -> float | None:
        stats = self.coordinator.data.get("interface_stats", {})
        iface_stats = stats.get(self._iface_name, {})
        txbytes = iface_stats.get("txbytes", 0)
        if txbytes:
            return round(float(txbytes) / (1024 ** 3), 2)
        return 0.0


class KeeneticWifi5RxSensor(ControllerEntity, SensorEntity):
    """WiFi 5GHz RX sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "wifi_5_rx"
    _attr_icon = "mdi:download-network"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._iface_name = "WifiMaster1"
        self._band = "5GHz"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wifi_5_rx"

    @property
    def name(self) -> str:
        return f"WiFi {self._band} RX"

    @property
    def native_value(self) -> float | None:
        stats = self.coordinator.data.get("interface_stats", {})
        iface_stats = stats.get(self._iface_name, {})
        rxbytes = iface_stats.get("rxbytes", 0)
        if rxbytes:
            return round(float(rxbytes) / (1024 ** 3), 2)
        return 0.0


class KeeneticWifi5TxSensor(ControllerEntity, SensorEntity):
    """WiFi 5GHz TX sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "wifi_5_tx"
    _attr_icon = "mdi:upload-network"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_native_unit_of_measurement = UnitOfInformation.GIGABYTES
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._iface_name = "WifiMaster1"
        self._band = "5GHz"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wifi_5_tx"

    @property
    def name(self) -> str:
        return f"WiFi {self._band} TX"

    @property
    def native_value(self) -> float | None:
        stats = self.coordinator.data.get("interface_stats", {})
        iface_stats = stats.get(self._iface_name, {})
        txbytes = iface_stats.get("txbytes", 0)
        if txbytes:
            return round(float(txbytes) / (1024 ** 3), 2)
        return 0.0


class KeeneticLanRxSensor(ControllerEntity, SensorEntity):
    """LAN (GigabitEthernet0) RX sensor."""
    _attr_has_entity_name = True
    _attr_translation_key = "lan_rx"
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
    _attr_translation_key = "lan_tx"
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
    _attr_translation_key = "wan_rx"
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
    _attr_translation_key = "wan_tx"
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

class KeeneticFirmwareVersionSensor(ControllerEntity, SensorEntity):
    """Current firmware version sensor for the main router."""
    _attr_has_entity_name = True
    _attr_translation_key = "firmware_version"
    _attr_icon = "mdi:package-variant-closed"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_firmware_version"

    @property
    def name(self) -> str:
        return "Firmware Version"

    @property
    def native_value(self) -> str | None:
        return self._firmware_version

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        system = self.coordinator.data.get("system", {}) or {}
        attrs: dict[str, Any] = {}
        if system.get("release"):
            attrs["release"] = system["release"]
        if system.get("fw-update-sandbox"):
            attrs["channel"] = system["fw-update-sandbox"]
        if system.get("arch"):
            attrs["architecture"] = system["arch"]
        ndm = system.get("ndm")
        if isinstance(ndm, dict) and ndm.get("exact"):
            attrs["ndm_version"] = ndm["exact"]
        bsp = system.get("bsp")
        if isinstance(bsp, dict) and bsp.get("exact"):
            attrs["bsp_version"] = bsp["exact"]
        return attrs if attrs else None


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
        return f"{safe_cid}_firmware_version"

    @property
    def name(self) -> str:
        return "Firmware Version"

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
