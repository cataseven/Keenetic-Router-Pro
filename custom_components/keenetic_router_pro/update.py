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

    # Mesh node firmware update entities (info-only, no install)
    mesh_nodes = coordinator.data.get("mesh_nodes", [])
    for node in mesh_nodes:
        node_cid = node.get("cid") or node.get("id")
        if node_cid:
            entities.append(
                KeeneticMeshFirmwareUpdate(coordinator, entry, node_cid)
            )

    async_add_entities(entities)


class KeeneticFirmwareUpdate(ControllerEntity, UpdateEntity):
    """Firmware update entity for the main Keenetic router."""

    _attr_has_entity_name = True
    _attr_name = "Firmware Update"
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
        available = system.get("fw-available") or system.get("release-available")
        current = system.get("title") or system.get("release")

        # Only report as available if it differs from current
        # and the update channel is stable
        if (
            available
            and current
            and available != current
            and system.get("fw-update-sandbox", "stable") == "stable"
        ):
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
            return (
                f"**{model}** firmware update available\n\n"
                f"- Current: `{current}`\n"
                f"- Available: `{available}`\n"
                f"- Channel: {channel}\n\n"
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

            # Poll progress until complete or timeout
            import asyncio

            for _ in range(120):  # ~2 min max polling
                await asyncio.sleep(2)

                try:
                    progress = await self._client.async_get_update_progress()
                except Exception:
                    # Connection lost likely means router is rebooting
                    self._update_progress = 95
                    self.async_write_ha_state()
                    break

                if not progress.get("in_progress", False):
                    break

                percent = progress.get("progress_percent", 0)
                if isinstance(percent, (int, float)) and 0 <= percent <= 100:
                    self._update_progress = int(percent)
                    self.async_write_ha_state()

        except HomeAssistantError:
            raise
        except Exception as err:
            _LOGGER.error("Firmware update failed: %s", err)
            raise HomeAssistantError(f"Firmware update failed: {err}") from err
        finally:
            self._update_progress = None
            self.async_write_ha_state()

        # Refresh coordinator to pick up new version
        await self.coordinator.async_request_refresh()


class KeeneticMeshFirmwareUpdate(MeshEntity, UpdateEntity):
    """Firmware update entity for a Keenetic mesh node (info-only)."""

    _attr_has_entity_name = True
    _attr_name = "Firmware Update"
    _attr_device_class = UpdateDeviceClass.FIRMWARE
    # Mesh nodes update via the controller, so no install feature
    _attr_supported_features = UpdateEntityFeature(0)

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        node_cid: str,
    ) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_firmware_update"

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
            return available
        return current

    @property
    def release_url(self) -> str | None:
        """Return the release notes URL."""
        return KEENETIC_RELEASE_NOTES_URL
