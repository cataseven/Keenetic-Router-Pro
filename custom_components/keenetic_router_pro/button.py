"""Buttons for Keenetic Router Pro (e.g. reboot)."""
from __future__ import annotations
import logging
from typing import Any
from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .api import KeeneticClient
from .const import DOMAIN, DATA_CLIENT, DATA_COORDINATOR, CONF_TRACKED_CLIENTS
from .coordinator import KeeneticCoordinator
from .entity import ControllerEntity, MeshEntity, ClientEntity

_LOGGER = logging.getLogger(__name__)


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

    # Per-client "Clear Bandwidth Limit" button (issue #42).
    # HA's number frontend rejects empty input with a schema-level
    # "expected float" error before our code is reached, so the only
    # way to clear a limit via the slider is typing 0 explicitly.
    # This button gives users a one-tap alternative and routes through
    # the same async_set_client_bandwidth(mac, 0) path the slider uses
    # internally — running config save included.
    tracked_clients = entry.data.get(CONF_TRACKED_CLIENTS, [])
    for client_info in tracked_clients:
        if not isinstance(client_info, dict):
            continue
        mac = str(client_info.get("mac") or "").lower()
        if not mac:
            continue
        name = client_info.get("name") or mac.upper()
        initial_ip = client_info.get("ip")
        entities.append(
            KeeneticClientClearBandwidthButton(
                coordinator=coordinator,
                entry=entry,
                api_client=client,
                mac=mac,
                label=name,
                initial_ip=initial_ip,
            )
        )
        entities.append(
            KeeneticClientWakeOnLanButton(
                coordinator=coordinator,
                entry=entry,
                api_client=client,
                mac=mac,
                label=name,
                initial_ip=initial_ip,
            )
        )

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
        return f"{safe_cid}_reboot_button_v2"

    @property
    def name(self) -> str:
        node = self._node
        node_name = node.get("name") if node else None
        if node_name:
            return f"Reboot {node_name}"
        return "Reboot"

    async def async_press(self, **_: Any) -> None:
        await self._client.async_reboot_mesh_node(self._node_cid)

class KeeneticClientClearBandwidthButton(ClientEntity, ButtonEntity):
    """One-tap "remove bandwidth limit" button per tracked client.

    Companion to the ``KeeneticClientBandwidthLimitNumber`` slider —
    HA's number frontend rejects an empty input with a schema-level
    error before our service handler runs, so users couldn't clear
    a limit just by erasing the field. This button gives them a
    direct path that works around the frontend constraint.
    """
    _attr_has_entity_name = True
    _attr_icon = "mdi:speedometer-slow"

    # Per-client buttons share the client device card with the slider;
    # they don't read coordinator data themselves, so the fingerprint
    # dedup machinery doesn't apply.
    _FINGERPRINT_IGNORE: frozenset = frozenset()

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        api_client: KeeneticClient,
        mac: str,
        label: str,
        initial_ip: str | None,
    ) -> None:
        ClientEntity.__init__(
            self,
            coordinator=coordinator,
            entry_id=entry.entry_id,
            title=entry.title,
            mac=mac,
            label=label,
            initial_ip=initial_ip,
        )
        self._api_client = api_client

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_clear_bandwidth"

    @property
    def name(self) -> str:
        return "Clear Bandwidth Limit"

    async def async_press(self, **_: Any) -> None:
        try:
            await self._api_client.async_set_client_bandwidth(self._mac, 0)
        except Exception:  # noqa: BLE001
            _LOGGER.exception(
                "Failed to clear bandwidth limit for client %s", self._mac
            )
            raise
        await self.coordinator.async_request_refresh()

class KeeneticClientWakeOnLanButton(ClientEntity, ButtonEntity):
    """One-tap Wake-on-LAN button per tracked client.

    Mirrors the "Wake on LAN" action available for a client in the Keenetic
    web UI / My.Keenetic app, sending a magic packet to the client's MAC
    address via the router's ``ip hotspot wake`` CLI command.
    """
    _attr_has_entity_name = True
    _attr_icon = "mdi:power"

    # Per-client buttons share the client device card with the slider;
    # they don't read coordinator data themselves, so the fingerprint
    # dedup machinery doesn't apply.
    _FINGERPRINT_IGNORE: frozenset = frozenset()

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        api_client: KeeneticClient,
        mac: str,
        label: str,
        initial_ip: str | None,
    ) -> None:
        ClientEntity.__init__(
            self,
            coordinator=coordinator,
            entry_id=entry.entry_id,
            title=entry.title,
            mac=mac,
            label=label,
            initial_ip=initial_ip,
        )
        self._api_client = api_client

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_client_{self._mac}_wol"

    @property
    def name(self) -> str:
        return "Wake on LAN"

    async def async_press(self, **_: Any) -> None:
        try:
            await self._api_client.async_wake_client(self._mac)
        except Exception:  # noqa: BLE001
            _LOGGER.exception(
                "Failed to send Wake-on-LAN packet to client %s", self._mac
            )
            raise
