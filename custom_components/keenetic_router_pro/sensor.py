"""Sensors for Keenetic Router Pro."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfInformation, UnitOfTime, PERCENTAGE
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, DATA_COORDINATOR
from .coordinator import KeeneticCoordinator


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
    
    # Yeni sensörler
    entities.append(KeeneticWanIpSensor(coordinator, entry))
    entities.append(KeeneticConnectedClientsSensor(coordinator, entry))
    entities.append(KeeneticDisconnectedClientsSensor(coordinator, entry))
    entities.append(KeeneticExtenderCountSensor(coordinator, entry))
    entities.append(KeeneticPppoeUptimeSensor(coordinator, entry))
    entities.append(KeeneticActiveConnectionsSensor(coordinator, entry))
    
    mesh_nodes = coordinator.data.get("mesh_nodes", [])
    for node in mesh_nodes:
        node_cid = node.get("cid") or node.get("id")
        if node_cid:
            entities.append(KeeneticMeshFirmwareSensor(coordinator, entry, node_cid))

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


class BaseKeeneticSensor(CoordinatorEntity, SensorEntity):
    """Base class for Keenetic sensors sharing device_info."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._entry = entry

    @property
    def device_info(self) -> dict[str, Any]:
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": self._entry.title,
            "manufacturer": "Keenetic",
        }

    @property
    def _system(self) -> dict[str, Any]:
        return self.coordinator.data.get("system", {}) or {}


class KeeneticCpuLoadSensor(BaseKeeneticSensor):
    """CPU yükü sensörü."""

    _attr_translation_key = "cpu_load"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_cpu_load"

    @property
    def name(self) -> str:
        return "CPU Load"

    @property
    def native_unit_of_measurement(self) -> str:
        return PERCENTAGE

    @property
    def native_value(self) -> float | None:
        # Farklı firmware'lerde farklı key'ler kullanılabiliyor
        sys = self._system
        for key in ("cpu_load", "cpuload", "cpu", "cpu-utilization"):
            if key in sys:
                return float(sys[key])
        return None


class KeeneticMemoryUsageSensor(BaseKeeneticSensor):
    """RAM kullanım yüzdesi sensörü."""

    _attr_translation_key = "memory_usage"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_mem_usage"

    @property
    def name(self) -> str:
        return "Memory Usage"

    @property
    def native_unit_of_measurement(self) -> str:
        return PERCENTAGE

    @property
    def native_value(self) -> float | None:
        sys = self._system

        mem = sys.get("memory") or sys.get("mem")
        memtotal = sys.get("memtotal")
        memfree = sys.get("memfree")

        # 1) "memory": "used/total" string (Keenetic böyle yapıyor)
        if isinstance(mem, str) and "/" in mem:
            try:
                part_used, part_total = mem.split("/", 1)
                used = float(part_used)
                total = float(part_total)
                if total > 0:
                    return round(used * 100.0 / total, 1)
            except (ValueError, TypeError):
                pass

        # 2) memtotal / memfree ayrı alanlar olarak varsa
        if isinstance(memtotal, (int, float)) and isinstance(memfree, (int, float)) and memtotal > 0:
            used = memtotal - memfree
            return round(used * 100.0 / memtotal, 1)

        # 3) Bazı firmware'lerde doğrudan yüzde dönebiliyor
        for key in ("mem_used_percent", "memory_usage", "memusage"):
            if key in sys:
                try:
                    return float(sys[key])
                except (TypeError, ValueError):
                    continue

        return None



class KeeneticUptimeSensor(BaseKeeneticSensor):
    """Router uptime sensörü."""

    _attr_translation_key = "uptime"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_uptime"

    @property
    def name(self) -> str:
        return "Uptime"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfTime.SECONDS

    @property
    def native_value(self) -> int:
        """Uptime değeri saniye cinsinden.

        Değer yoksa veya parse edilemiyorsa 0 döner (Unknown yerine 0s).
        """
        sys = self._system

        candidates: list[Any] = []

        # Bazı firmware'lerde düz root'ta: {"uptime": "12345"}
        for key in ("uptime", "uptime_sec", "uptime_seconds"):
            if key in sys:
                candidates.append(sys.get(key))

        # Bazı firmware'lerde nested: {"system": {"uptime": "..."}}
        nested = sys.get("system")
        if isinstance(nested, dict):
            for key in ("uptime", "uptime_sec", "uptime_seconds"):
                if key in nested:
                    candidates.append(nested.get(key))

        for value in candidates:
            if value in (None, "", "unknown", "Unknown"):
                continue
            try:
                # string veya float gelebilir
                return int(float(value))
            except (TypeError, ValueError):
                continue

        # Hiçbir şey bulunamazsa 0 saniye göster (Unavailable yerine 0s).
        return 0




class KeeneticWanStatusSensor(BaseKeeneticSensor):
    """Basit WAN bağlantı durumu sensörü (up/down)."""

    _attr_translation_key = "wan_status"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_wan_status"

    @property
    def name(self) -> str:
        return "WAN Status"

    @property
    def native_value(self) -> str | None:
        interfaces = self.coordinator.data.get("interfaces") or {}

        # interfaces hem dict hem list olabildiği için normalize edelim
        if isinstance(interfaces, dict):
            iface_list = list(interfaces.values())
        elif isinstance(interfaces, list):
            iface_list = interfaces
        else:
            iface_list = []

        if not iface_list:
            return "down"

        # WAN interface'i: state=up ve adında / açıklamasında WAN/Internet/PPPoE/ISP geçen ilk arayüz
        WAN_KEYWORDS = ("wan", "internet", "pppoe", "isp")

        for iface in iface_list:
            state = str(iface.get("state") or "").lower()

            # İsim olabilecek tüm alanları toplayıp tek stringte birleştir
            name_fields = [
                iface.get("name"),
                iface.get("ifname"),
                iface.get("id"),
                iface.get("interface-name"),
                iface.get("description"),
                iface.get("type"),
            ]
            name_joined = " ".join(str(v) for v in name_fields if v).lower()

            if state == "up" and any(k in name_joined for k in WAN_KEYWORDS):
                return "up"

        return "down"


class _BaseWgSensor(BaseKeeneticSensor):
    """WireGuard ortak mantığı."""

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, wg_name: str) -> None:
        super().__init__(coordinator, entry)
        # wg_name: interface id (Wireguard0, Wireguard1...)
        self._wg_name = wg_name

    @property
    def _wg_profiles(self) -> dict[str, Any]:
        """Return full WireGuard profiles mapping from coordinator data."""
        return self.coordinator.data.get("wireguard", {}).get("profiles", {}) or {}

    @property
    def _wg(self) -> dict[str, Any]:
        """Return this sensor's WireGuard profile data (may be empty)."""
        return self._wg_profiles.get(self._wg_name, {}) or {}

    @property
    def _wg_label(self) -> str:
        """Kullanıcıya gösterilecek tünel adı (label), yoksa id."""
        profile = self._wg
        label = profile.get("label")
        if isinstance(label, str) and label.strip():
            return label.strip()
        return self._wg_name



class KeeneticWgUptimeSensor(_BaseWgSensor):
    """WireGuard tünel uptime sensörü."""

    _attr_translation_key = "wireguard_uptime"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_wg_{self._wg_name}_uptime"

    @property
    def name(self) -> str:
        # Örn: "WireGuard Zurich Uptime"
        return f"WireGuard {self._wg_label} Uptime"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfTime.SECONDS

    @property
    def native_value(self) -> int:
        """Uptime değeri saniye cinsinden.

        Bilgi yoksa veya 'unknown' vs. gelirse 0 döner.
        """
        for key in ("uptime", "uptime_sec", "uptime_seconds"):
            value = self._wg.get(key)
            if value in (None, "", "unknown", "Unknown"):
                continue
            try:
                return int(float(value))
            except (TypeError, ValueError):
                continue

        # Tünel kapalıyken / hiç up olmamışken:
        return 0



class KeeneticWgRxSensor(_BaseWgSensor):
    """WireGuard RX (alınan trafik) sensörü."""

    _attr_translation_key = "wireguard_rx"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_wg_{self._wg_name}_rx"

    @property
    def name(self) -> str:
        # Örn: "WireGuard Zurich RX"
        return f"WireGuard {self._wg_label} RX"


    @property
    def native_unit_of_measurement(self) -> str:
        # Byte yerine MB göster.
        return UnitOfInformation.MEGABYTES

    @property
    def native_value(self) -> float | None:
        """RX miktarı MB cinsinden.

        Değer yoksa / None ise veya parse edilemiyorsa None döner.
        """
        for key in ("rxbytes", "rx", "received"):
            value = self._wg.get(key)
            if value in (None, ""):
                continue
            try:
                bytes_val = float(value)
                # 1 MB ~ 1024 * 1024 byte
                return round(bytes_val / (1024 * 1024), 2)
            except (TypeError, ValueError):
                continue
        return None



class KeeneticWgTxSensor(_BaseWgSensor):
    """WireGuard TX (gönderilen trafik) sensörü."""

    _attr_translation_key = "wireguard_tx"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_wg_{self._wg_name}_tx"

    @property
    def name(self) -> str:
        # Örn: "WireGuard Zurich TX"
        return f"WireGuard {self._wg_label} TX"


    @property
    def native_unit_of_measurement(self) -> str:
        # Byte yerine MB göster.
        return UnitOfInformation.MEGABYTES

    @property
    def native_value(self) -> float | None:
        """TX miktarı MB cinsinden.

        Değer yoksa / None ise veya parse edilemiyorsa None döner.
        """
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


class KeeneticWanIpSensor(BaseKeeneticSensor):
    """WAN IP adresi sensörü."""

    _attr_translation_key = "wan_ip"
    _attr_icon = "mdi:ip-network"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_wan_ip"

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


class KeeneticPppoeUptimeSensor(BaseKeeneticSensor):
    """PPPoE bağlantı uptime sensörü."""

    _attr_translation_key = "pppoe_uptime"
    _attr_icon = "mdi:timer-outline"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_pppoe_uptime"

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


class KeeneticActiveConnectionsSensor(BaseKeeneticSensor):
    """Aktif bağlantı sayısı sensörü (conntotal - connfree)."""

    _attr_translation_key = "active_connections"
    _attr_icon = "mdi:connection"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_active_connections"

    @property
    def name(self) -> str:
        return "Active Connections"

    @property
    def native_value(self) -> int:
        sys = self._system
        conntotal = sys.get("conntotal", 0)
        connfree = sys.get("connfree", 0)
        try:
            return int(conntotal) - int(connfree)
        except (TypeError, ValueError):
            return 0

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        sys = self._system
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


class KeeneticConnectedClientsSensor(BaseKeeneticSensor):
    """Bağlı cihaz sayısı sensörü."""

    _attr_translation_key = "connected_clients"
    _attr_icon = "mdi:devices"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_connected_clients"

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


class KeeneticDisconnectedClientsSensor(BaseKeeneticSensor):
    """Bağlı olmayan (bilinen) cihaz sayısı sensörü."""

    _attr_translation_key = "disconnected_clients"
    _attr_icon = "mdi:devices-off"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_disconnected_clients"

    @property
    def name(self) -> str:
        return "Disconnected Clients"

    @property
    def native_value(self) -> int:
        stats = self.coordinator.data.get("client_stats", {})
        return stats.get("disconnected", 0)


class KeeneticExtenderCountSensor(BaseKeeneticSensor):
    """Mesh extender/repeater sayısı sensörü."""

    _attr_translation_key = "extender_count"
    _attr_icon = "mdi:access-point-network"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_extender_count"

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
        
        # Node listesi
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


class KeeneticDownloadSpeedSensor(BaseKeeneticSensor):
    """Anlık indirme hızı sensörü."""

    _attr_translation_key = "download_speed"
    _attr_icon = "mdi:download-network"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_download_speed"

    @property
    def name(self) -> str:
        return "Download Speed"

    @property
    def native_unit_of_measurement(self) -> str:
        return "MB/s"

    @property
    def native_value(self) -> float:
        stats = self.coordinator.data.get("traffic_stats", {})
        return stats.get("download_speed", 0.0)


class KeeneticUploadSpeedSensor(BaseKeeneticSensor):
    """Anlık yükleme hızı sensörü."""

    _attr_translation_key = "upload_speed"
    _attr_icon = "mdi:upload-network"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_upload_speed"

    @property
    def name(self) -> str:
        return "Upload Speed"

    @property
    def native_unit_of_measurement(self) -> str:
        return "MB/s"

    @property
    def native_value(self) -> float:
        stats = self.coordinator.data.get("traffic_stats", {})
        return stats.get("upload_speed", 0.0)


class KeeneticTotalDownloadSensor(BaseKeeneticSensor):
    """Toplam indirilen veri sensörü."""

    _attr_translation_key = "total_download"
    _attr_icon = "mdi:download"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_total_download"

    @property
    def name(self) -> str:
        return "Total Downloaded"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfInformation.GIGABYTES

    @property
    def native_value(self) -> float:
        stats = self.coordinator.data.get("traffic_stats", {})
        total_rx = stats.get("total_rx", 0)
        # Bytes -> GB
        return round(float(total_rx) / (1024 ** 3), 2)


class KeeneticTotalUploadSensor(BaseKeeneticSensor):
    """Toplam yüklenen veri sensörü."""

    _attr_translation_key = "total_upload"
    _attr_icon = "mdi:upload"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_total_upload"

    @property
    def name(self) -> str:
        return "Total Uploaded"

    @property
    def native_unit_of_measurement(self) -> str:
        return UnitOfInformation.GIGABYTES

    @property
    def native_value(self) -> float:
        stats = self.coordinator.data.get("traffic_stats", {})
        total_tx = stats.get("total_tx", 0)
        # Bytes -> GB
        return round(float(total_tx) / (1024 ** 3), 2)


class KeeneticUsbStorageSensor(BaseKeeneticSensor):
    """USB depolama sensörü."""

    _attr_translation_key = "usb_storage"
    _attr_icon = "mdi:usb-flash-drive"

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, device_id: str) -> None:
        super().__init__(coordinator, entry)
        self._device_id = device_id

    @property
    def _device(self) -> dict[str, Any] | None:
        """Get current device data."""
        devices = self.coordinator.data.get("usb_storage", [])
        for device in devices:
            if device.get("id") == self._device_id:
                return device
        return None

    @property
    def unique_id(self) -> str:
        safe_id = self._device_id.replace("/", "_").replace(" ", "_").lower()
        return f"{self._entry.entry_id}_usb_{safe_id}"

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
        """Return used percentage."""
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
        
        # Yüzde hesapla
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


class KeeneticMeshFirmwareSensor(BaseKeeneticSensor):
    """Mesh node firmware güncelleme sensörü."""

    _attr_translation_key = "mesh_firmware"
    _attr_icon = "mdi:update"

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry, node_cid: str) -> None:
        super().__init__(coordinator, entry)
        self._node_cid = node_cid

    @property
    def _node(self) -> dict[str, Any] | None:
        """Get current node data."""
        nodes = self.coordinator.data.get("mesh_nodes", [])
        for node in nodes:
            if (node.get("cid") or node.get("id")) == self._node_cid:
                return node
        return None

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "")[:16]
        return f"{self._entry.entry_id}_mesh_{safe_cid}_firmware"

    @property
    def name(self) -> str:
        node = self._node
        if node:
            node_name = node.get("name") or node.get("mac") or self._node_cid
            return f"Mesh - {node_name} Firmware"
        return f"Mesh - {self._node_cid} Firmware"

    @property
    def native_value(self) -> str | None:
        """Return current firmware version."""
        node = self._node
        if node:
            return node.get("firmware")
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        node = self._node
        if not node:
            return None
        
        current = node.get("firmware")
        available = node.get("firmware_available")
        
        # Güncelleme var mı?
        update_available = False
        if current and available and current != available:
            update_available = True
        
        return {
            "cid": self._node_cid,
            "model": node.get("model"),
            "current_version": current,
            "available_version": available,
            "update_available": update_available,
        }


class KeeneticMeshUsbStorageSensor(BaseKeeneticSensor):
    """USB depolama sensörü - Mesh node üzerindeki USB."""

    _attr_translation_key = "mesh_usb_storage"
    _attr_icon = "mdi:usb-flash-drive"

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        device_id: str,
        mesh_node_name: str | None = None,
        mesh_cid: str | None = None,
    ) -> None:
        super().__init__(coordinator, entry)
        self._device_id = device_id
        self._mesh_node_name = mesh_node_name or "Unknown"
        self._mesh_cid = mesh_cid

    @property
    def _device(self) -> dict[str, Any] | None:
        """Get current device data from mesh USB list."""
        devices = self.coordinator.data.get("mesh_usb", [])
        for device in devices:
            if device.get("id") == self._device_id:
                return device
        return None

    @property
    def unique_id(self) -> str:
        safe_id = self._device_id.replace("/", "_").replace(" ", "_").lower()
        safe_cid = (self._mesh_cid or "unknown").replace("-", "")[:12]
        return f"{self._entry.entry_id}_mesh_{safe_cid}_usb_{safe_id}"

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
        """Return used space in GB."""
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

