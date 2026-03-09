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
    def device_info(self) -> DeviceInfo:
        return get_main_device_info(self._title, self._entry_id)


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