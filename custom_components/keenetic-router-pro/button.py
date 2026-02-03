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


class KeeneticRebootButton(ButtonEntity):
    """Button to reboot the router."""

    _attr_has_entity_name = True
    _attr_name = "Reboot router"

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        client: KeeneticClient,
    ) -> None:
        self._coordinator = coordinator
        self._entry = entry
        self._client = client

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_reboot_button"

    @property
    def device_info(self) -> dict[str, Any]:
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": self._entry.title,
            "manufacturer": "Keenetic",
        }

    async def async_press(self, **_: Any) -> None:
        # İstersen burada persistent_notification ile "emin misin" diyebilirsin.
        await self._client.async_reboot()
        # Reboot sonrası router kısa süre offline olacak;
        # coordinator otomatik olarak bir sonraki denemede toparlar.


class KeeneticMeshRebootButton(ButtonEntity):
    """Button to reboot a mesh/extender node."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:restart"

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        client: KeeneticClient,
        node_cid: str,
    ) -> None:
        self._coordinator = coordinator
        self._entry = entry
        self._client = client
        self._node_cid = node_cid

    @property
    def _node(self) -> dict[str, Any] | None:
        """Get current node data from coordinator."""
        nodes = self._coordinator.data.get("mesh_nodes", [])
        for node in nodes:
            if (node.get("cid") or node.get("id")) == self._node_cid:
                return node
        return None

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "").replace(":", "")[:16]
        return f"{self._entry.entry_id}_mesh_{safe_cid}_reboot"

    @property
    def name(self) -> str:
        node = self._node
        if node:
            node_name = node.get("name") or node.get("mac") or self._node_cid
            return f"Mesh - Reboot {node_name}"
        return f"Mesh - Reboot {self._node_cid}"

    @property
    def device_info(self) -> dict[str, Any]:
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": self._entry.title,
            "manufacturer": "Keenetic",
        }

    async def async_press(self, **_: Any) -> None:
        await self._client.async_reboot_mesh_node(self._node_cid)
