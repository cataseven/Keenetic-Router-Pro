"""Base entity classes for Keenetic Router Pro."""
from typing import Any, Dict, Optional
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.device_registry import DeviceInfo
from .const import DOMAIN
from .coordinator import KeeneticCoordinator
from .utils import get_main_device_info, get_mesh_device_info


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
        return get_main_device_info(
            self._title, 
            self._entry_id,
            self._firmware_version,
            self._model_name,
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
        return get_mesh_device_info(
            self._title,
            self._entry_id,
            self._node,
            self._node_cid,
        )