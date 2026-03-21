"""Base entity classes for Keenetic Router Pro."""
from typing import Any, Dict, Optional
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.device_registry import DeviceInfo
from .const import DOMAIN
from .coordinator import KeeneticCoordinator, KeeneticPingCoordinator
from .utils import get_main_device_info, get_mesh_device_info, get_client_device_info


class ControllerEntity(CoordinatorEntity):
    """Базовый класс для сущностей главного роутера."""
    
    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry_id: str,
        title: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._title = title
    
    @property
    def _version_data(self) -> Dict[str, Any]:
        """Получить данные версии из /rci/show/version."""
        # Данные из coordinator.data["system"] — это ответ от /rci/show/version
        return self.coordinator.data.get("system", {}) or {}
    
    @property
    def _firmware_version(self) -> Optional[str]:
        """Получить версию прошивки.
        
        Данные приходят из merged system+version в coordinator.data["system"]
        """
        version = self.coordinator.data.get("system", {}) or {}
        
        if version.get("title"):
            return str(version["title"])
        if version.get("release"):
            return str(version["release"])
        
        ndw4 = version.get("ndw4", {})
        if isinstance(ndw4, dict) and ndw4.get("version"):
            return str(ndw4["version"])
        
        return None

    @property
    def _model_name(self) -> Optional[str]:
        """Получить модель роутера.
        
        Приоритет: model > description > device > hw_id
        """
        version = self.coordinator.data.get("system", {}) or {}
        
        if version.get("model"):
            return str(version["model"])
        if version.get("description"):
            return str(version["description"])
        if version.get("device"):
            return str(version["device"])
        if version.get("hw_id"):
            return str(version["hw_id"])
        
        return None
    
    @property
    def device_info(self) -> DeviceInfo:
        ndns_info = self.coordinator.data.get("ndns", {})
        ndns_domain = None
        
        if ndns_info:
            name = ndns_info.get("name")
            domain = ndns_info.get("domain")
            if name and domain:
                ndns_domain = f"{name}.{domain}"
        
        return get_main_device_info(
            self._title, 
            self._entry_id,
            self._firmware_version,
            self._model_name,
            host=self.coordinator._client._host if hasattr(self.coordinator, '_client') else None,
            ssl=self.coordinator._client._ssl if hasattr(self.coordinator, '_client') else False,
            ndns_domain=ndns_domain,
        )


class MeshEntity(CoordinatorEntity):
    """Базовый класс для сущностей Mesh-ноды."""
    
    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry_id: str,
        title: str,
        node_cid: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._title = title
        self._node_cid = node_cid
    
    @property
    def _node(self) -> Optional[Dict[str, Any]]:
        """Получить данные ноды из coordinator."""
        nodes = self.coordinator.data.get("mesh_nodes", [])
        for node in nodes:
            if (node.get("cid") or node.get("id")) == self._node_cid:
                return node
        return None
    
    @property
    def device_info(self) -> DeviceInfo:
        node = self._node
        node_ip = node.get("ip") if node else None
        
        return get_mesh_device_info(
            self._title,
            self._entry_id,
            self._node,
            self._node_cid,
            host=node_ip,
            ssl=self.coordinator._client._ssl if hasattr(self.coordinator, '_client') else False,
            fqdn=node.get("fqdn")
        )
    
class ClientEntity(CoordinatorEntity):
    """Базовый класс для сущностей отслеживаемых клиентов как отдельных устройств."""
    
    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry_id: str,
        title: str,
        mac: str,
        label: str,
        initial_ip: Optional[str] = None,
        ping_coordinator = None,  # Optional, for ping tracking
    ) -> None:
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._title = title
        self._mac = mac.lower()
        self._label = label
        self._initial_ip = initial_ip
        self._ping_coordinator = ping_coordinator  # Это должен быть объект, не строка
    
    @property
    def _client(self) -> Optional[Dict[str, Any]]:
        """Получить данные клиента из coordinator."""
        clients = self.coordinator.data.get("clients", []) or []
        for client in clients:
            if str(client.get("mac") or "").lower() == self._mac:
                return client
        return None
    
    @property
    def device_info(self) -> DeviceInfo:
        """Device info для отслеживаемого клиента как отдельного устройства."""
        client = self._client
        return get_client_device_info(
            entry_id=self._entry_id,
            mac=self._mac,
            label=self._label,
            client=client,
            initial_ip=self._initial_ip,
        )
    
    @property
    def ip_address(self) -> Optional[str]:
        """Get current IP address of the client."""
        client = self._client
        if client:
            ip = client.get("ip")
            if ip:
                return str(ip)
        return self._initial_ip
    
    @property
    def hostname(self) -> Optional[str]:
        """Get hostname of the client."""
        client = self._client
        if not client:
            return self._label
        
        name = client.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        h = client.get("hostname")
        if isinstance(h, str) and h.strip():
            return h.strip()
        return self._label
    
    @property
    def _is_apple_device(self) -> bool:
        """Check if this is likely an Apple device."""
        name = self._label or ""
        name_lower = name.lower()
        return any(kw in name_lower for kw in ("apple", "iphone", "ipad", "macbook", "imac"))
    
    @property
    def is_connected(self) -> bool:
        """Determine if device is connected."""
        # Проверяем, что ping_coordinator - это объект, а не строка
        if self._ping_coordinator and hasattr(self._ping_coordinator, 'data') and not self._is_apple_device:
            ping_results = self._ping_coordinator.data or {}
            return ping_results.get(self._mac, False)
        else:
            client = self._client
            if client:
                return str(client.get("link", "")).lower() == "up"
            return False