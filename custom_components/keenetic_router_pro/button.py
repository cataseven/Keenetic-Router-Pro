"""Buttons for Keenetic Router Pro (e.g. reboot)."""
from __future__ import annotations
from typing import Any
from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .api import KeeneticClient
from .const import DOMAIN, DATA_CLIENT, DATA_COORDINATOR
from .coordinator import KeeneticCoordinator
from .entity import ControllerEntity, MeshEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic Router Pro buttons."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: KeeneticCoordinator = data[DATA_COORDINATOR]
    client: KeeneticClient = data[DATA_CLIENT]
    entities: list[ButtonEntity] = [KeeneticRebootButton(coordinator, entry, client)]

    # Mesh node reboot butonları
    mesh_nodes = coordinator.data.get("mesh_nodes", [])
    for node in mesh_nodes:
        node_cid = node.get("cid") or node.get("id")
        if node_cid:
            entities.append(KeeneticMeshRebootButton(coordinator, entry, client, node_cid))

    async_add_entities(entities)


class KeeneticRebootButton(ControllerEntity, ButtonEntity):
    """Button to reboot the router."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:restart"
    _attr_translation_key = "reboot"

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        client: KeeneticClient,
    ) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._client = client

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_reboot_button"

    async def async_press(self, **_: Any) -> None:
        await self._client.async_reboot()


class KeeneticMeshRebootButton(MeshEntity, ButtonEntity):
    """Button to reboot a mesh/extender node."""
    _attr_has_entity_name = True
    _attr_icon = "mdi:restart"
    _attr_translation_key = "mesh_reboot"

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        client: KeeneticClient,
        node_cid: str,
    ) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)
        self._client = client

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_reboot_button"

    async def async_press(self, **_: Any) -> None:
        await self._client.async_reboot_mesh_node(self._node_cid)