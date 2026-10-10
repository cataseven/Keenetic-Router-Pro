"""Firmware update platform for Keenetic Router Pro."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.update import (
    UpdateDeviceClass,
    UpdateEntity,
    UpdateEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import KeeneticClient
from .const import DOMAIN, DATA_CLIENT, DATA_COORDINATOR
from .coordinator import KeeneticCoordinator
from .entity import ControllerEntity, MeshEntity

_LOGGER = logging.getLogger(__name__)

KEENETIC_RELEASE_NOTES_URL = "https://help.keenetic.com/hc/en-us/categories/360000400920-KeeneticOS-Release-Notes"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic Router Pro update entities."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: KeeneticCoordinator = data[DATA_COORDINATOR]
    client: KeeneticClient = data[DATA_CLIENT]

    entities: list[UpdateEntity] = [
        KeeneticFirmwareUpdate(coordinator, entry, client),
    ]

    # Mesh node firmware update entities
    mesh_nodes = coordinator.data.get("mesh_nodes", [])
    for node in mesh_nodes:
        node_cid = node.get("cid") or node.get("id")
        if node_cid:
            entities.append(
                KeeneticMeshFirmwareUpdate(coordinator, entry, node_cid, client)
            )

    async_add_entities(entities)


class KeeneticFirmwareUpdate(ControllerEntity, UpdateEntity):
    """Firmware update entity for the main Keenetic router."""

    _attr_has_entity_name = True
    _attr_translation_key = "firmware_update"
    _attr_device_class = UpdateDeviceClass.FIRMWARE
    _attr_supported_features = (
        UpdateEntityFeature.INSTALL
        | UpdateEntityFeature.PROGRESS
        | UpdateEntityFeature.RELEASE_NOTES
    )

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        client: KeeneticClient,
    ) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._client = client
        self._update_progress: int | None = None

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_firmware_update"

    @property
    def installed_version(self) -> str | None:
        """Return the current firmware version."""
        system = self.coordinator.data.get("system", {}) or {}
        return system.get("title") or system.get("release")

    @property
    def latest_version(self) -> str | None:
        """Return the latest available firmware version."""
        system = self.coordinator.data.get("system", {}) or {}
        if not system.get("fw-update-known", True):
            # No update check has succeeded for this firmware yet. Say
            # "unknown": answering with the installed version would make
            # Home Assistant forget an update the user chose to skip.
            return None
        available = system.get("fw-available") or system.get("release-available")
        current = system.get("title") or system.get("release")

        # Show update if router reports one available, regardless of channel
        if (
            available
            and current
            and available != current
            and system.get("fw-update-available", True)
        ):
            # HA's UpdateEntity uses AwesomeVersion comparison (latest > installed).
            # When switching channels (e.g. dev→stable), the available version
            # may be numerically lower. Append a suffix to bypass version comparison.
            try:
                from awesomeversion import AwesomeVersion
                if AwesomeVersion(available) < AwesomeVersion(current):
                    return f"{available} (channel switch)"
            except Exception:
                pass
            return available

        # No update available → return current so HA shows "up to date"
        return current

    @property
    def in_progress(self) -> bool | int:
        """Return update progress."""
        if self._update_progress is not None:
            return self._update_progress
        return False

    @property
    def release_url(self) -> str | None:
        """Return the release notes URL."""
        return KEENETIC_RELEASE_NOTES_URL

    async def async_release_notes(self) -> str | None:
        """Return release notes for the latest version."""
        system = self.coordinator.data.get("system", {}) or {}
        available = system.get("fw-available") or system.get("release-available")
        current = system.get("title") or system.get("release")
        model = self._model_name or "Keenetic"
        channel = system.get("fw-update-sandbox", "stable")

        if available and current and available != current:
            notes = (
                f"**{model}** firmware update available\n\n"
                f"- Current: `{current}`\n"
                f"- Available: `{available}`\n"
                f"- Channel: {channel}\n\n"
            )
            if channel and channel != "stable":
                notes += f"⚠️ This is a **{channel}** release.\n\n"
            notes += (
                f"Visit [Keenetic Release Notes]({KEENETIC_RELEASE_NOTES_URL}) "
                f"for detailed changelog."
            )
            return notes
        return None

    async def async_install(
        self,
        version: str | None,
        backup: bool,
        **kwargs: Any,
    ) -> None:
        """Install the firmware update."""
        _LOGGER.info("Starting firmware update for Keenetic router")

        try:
            self._update_progress = 0
            self.async_write_ha_state()

            result = await self._client.async_start_firmware_update()

            if not result:
                self._update_progress = None
                self.async_write_ha_state()
                raise HomeAssistantError("Router did not accept the update command")

            import asyncio

            # Try to get initial progress to detect if endpoint is available
            progress_supported = False
            try:
                initial = await self._client.async_get_update_progress()
                progress_supported = bool(initial and initial.get("in_progress"))
            except Exception:
                pass

            if progress_supported:
                # Poll progress until complete or timeout
                for _ in range(120):  # ~4 min max polling
                    await asyncio.sleep(2)
                    try:
                        progress = await self._client.async_get_update_progress()
                    except Exception:
                        # Connection lost — router is likely rebooting
                        self._update_progress = 95
                        self.async_write_ha_state()
                        break

                    if not progress.get("in_progress", False):
                        break

                    percent = progress.get("progress_percent", 0)
                    if isinstance(percent, (int, float)) and 0 <= percent <= 100:
                        self._update_progress = int(percent)
                        self.async_write_ha_state()
            else:
                # No progress endpoint — wait for router to reboot
                _LOGGER.info(
                    "Update progress not available on this router, "
                    "waiting for reboot"
                )
                self._update_progress = 50
                self.async_write_ha_state()

                # Wait until connection is lost (router rebooting)
                for _ in range(60):  # ~2 min to start reboot
                    await asyncio.sleep(2)
                    try:
                        await self._client.async_get_system_info()
                    except Exception:
                        # Connection lost — router is rebooting
                        self._update_progress = 90
                        self.async_write_ha_state()
                        break

        except HomeAssistantError:
            raise
        except Exception as err:
            _LOGGER.error("Firmware update failed: %s", err)
            raise HomeAssistantError(f"Firmware update failed: {err}") from err
        finally:
            self._update_progress = None
            self.async_write_ha_state()

        # Refresh coordinator to pick up new version
        self._client.invalidate_firmware_check()
        await self.coordinator.async_request_refresh()


class KeeneticMeshFirmwareUpdate(MeshEntity, UpdateEntity):
    """Firmware update entity for a Keenetic mesh node."""

    _attr_has_entity_name = True
    _attr_translation_key = "firmware_update"
    _attr_device_class = UpdateDeviceClass.FIRMWARE
    _attr_supported_features = (
        UpdateEntityFeature.INSTALL
        | UpdateEntityFeature.RELEASE_NOTES
    )

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        node_cid: str,
        client: KeeneticClient,
    ) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)
        self._client = client

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_firmware_update_v2"

    @property
    def installed_version(self) -> str | None:
        """Return the current firmware version of the mesh node."""
        node = self._node
        if not node:
            return None
        return node.get("firmware")

    @property
    def latest_version(self) -> str | None:
        """Return the latest available firmware for the mesh node."""
        node = self._node
        if not node:
            return None
        available = node.get("firmware_available")
        current = node.get("firmware")

        if available and current and available != current:
            # HA's UpdateEntity uses AwesomeVersion comparison (latest > installed).
            # When switching channels (e.g. dev→stable), the available version
            # may be numerically lower. Append a suffix to bypass version comparison
            # and fall back to HA's != check.
            try:
                from awesomeversion import AwesomeVersion
                if AwesomeVersion(available) < AwesomeVersion(current):
                    return f"{available} (channel switch)"
            except Exception:
                pass
            return available
        return current

    @property
    def release_url(self) -> str | None:
        """Return the release notes URL."""
        return KEENETIC_RELEASE_NOTES_URL

    async def async_release_notes(self) -> str | None:
        """Return release notes for the latest version."""
        node = self._node
        if not node:
            return None
        available = node.get("firmware_available")
        current = node.get("firmware")
        name = node.get("name") or node.get("model") or self._node_cid

        if available and current and available != current:
            return (
                f"**{name}** firmware update available\n\n"
                f"- Current: `{current}`\n"
                f"- Available: `{available}`\n\n"
                f"Update is managed by the controller router.\n\n"
                f"Visit [Keenetic Release Notes]({KEENETIC_RELEASE_NOTES_URL}) "
                f"for detailed changelog."
            )
        return None

    async def async_install(
        self,
        version: str | None,
        backup: bool,
        **kwargs: Any,
    ) -> None:
        """Install firmware update for this mesh node via direct connection."""
        node = self._node
        node_name = (node.get("name") or self._node_cid) if node else self._node_cid
        node_ip = node.get("ip") if node else None

        if not node_ip:
            raise HomeAssistantError(
                f"Cannot update {node_name}: node IP address not available. "
                f"Is the node online?"
            )

        _LOGGER.info(
            "Starting firmware update for mesh node %s (%s)", node_name, node_ip
        )

        try:
            result = await self._client.async_start_node_firmware_update(
                node_ip=node_ip,
                node_name=node_name,
            )

            if not result:
                raise HomeAssistantError(
                    f"Node {node_name} did not accept the update command"
                )

            import asyncio

            _LOGGER.info(
                "Update started on %s, waiting for node to reboot", node_name
            )
            await asyncio.sleep(10)

            # Wait until node reports updated firmware or timeout
            for _ in range(90):  # ~3 min
                await asyncio.sleep(2)
                try:
                    await self.coordinator.async_request_refresh()
                    updated_node = self._node
                    if updated_node:
                        new_fw = updated_node.get("firmware")
                        avail = updated_node.get("firmware_available")
                        if new_fw and avail and new_fw == avail:
                            _LOGGER.info(
                                "Mesh node %s updated to %s", node_name, new_fw
                            )
                            break
                except Exception:
                    pass

        except HomeAssistantError:
            raise
        except Exception as err:
            _LOGGER.error("Mesh firmware update failed for %s: %s", node_name, err)
            raise HomeAssistantError(
                f"Mesh firmware update failed for {node_name}: {err}"
            ) from err

        await self.coordinator.async_request_refresh()
