"""Image platform for Keenetic Router Pro integration."""
from __future__ import annotations

import io
import logging
from typing import Any

import pyqrcode

from homeassistant.components.image import ImageEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
import homeassistant.util.dt as dt_util

from .const import DOMAIN, DATA_COORDINATOR
from .coordinator import KeeneticCoordinator

_LOGGER = logging.getLogger(__name__)


def _is_guest_wifi(network: dict[str, Any]) -> bool:
    """Return True if the given Wi-Fi network looks like a guest network."""
    ssid = str(network.get("ssid") or "").lower()
    description = str(network.get("description") or "").lower()
    interface_id = str(network.get("id") or "")
    return (
        "guest" in ssid
        or "guest" in description
        or "AccessPoint1" in interface_id
    )


def _band_rank(network: dict[str, Any]) -> int:
    """Rank bands so 5 GHz is preferred over 2.4 GHz when both are up."""
    band = str(network.get("band") or "").lower()
    if "5" in band:
        return 0  # best
    if "2.4" in band or band == "2":
        return 1
    return 2  # unknown last


def _select_best_network(
    candidates: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Pick the best Wi-Fi network for a QR code.

    Preference order:
      1. Enabled networks beat disabled networks.
      2. Among equals, 5 GHz beats 2.4 GHz beats unknown band.
      3. Stable: first in list wins on a tie.
    """
    if not candidates:
        return None

    def sort_key(idx_net: tuple[int, dict[str, Any]]) -> tuple[int, int, int]:
        idx, net = idx_net
        enabled_rank = 0 if net.get("enabled") else 1
        return (enabled_rank, _band_rank(net), idx)

    indexed = list(enumerate(candidates))
    indexed.sort(key=sort_key)
    return indexed[0][1]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic image entities."""
    coordinator: KeeneticCoordinator = hass.data[DOMAIN][entry.entry_id][DATA_COORDINATOR]
    images: list[ImageEntity] = []

    wifi_networks = coordinator.data.get("wifi", [])

    if not wifi_networks:
        _LOGGER.debug("No WiFi networks found, skipping QR images")
        async_add_entities(images)
        return

    mesh_nodes = coordinator.data.get("mesh_nodes", [])
    mesh_ips = {node.get("ip") for node in mesh_nodes if node.get("ip")}

    _LOGGER.debug("Found mesh nodes IPs: %s", mesh_ips)

    main_candidates: list[dict[str, Any]] = []
    guest_candidates: list[dict[str, Any]] = []

    for wifi_network in wifi_networks:
        ssid = wifi_network.get("ssid")
        if not ssid:
            continue

        interface_id = wifi_network.get("id", "")

        is_mesh = False
        for mesh_ip in mesh_ips:
            if mesh_ip in interface_id or mesh_ip in str(wifi_network):
                is_mesh = True
                break
        if is_mesh:
            _LOGGER.debug("Skipping mesh node interface: %s", interface_id)
            continue

        if _is_guest_wifi(wifi_network):
            guest_candidates.append(wifi_network)
        else:
            main_candidates.append(wifi_network)

    _LOGGER.debug(
        "Wi-Fi candidates for QR: main=%s, guest=%s",
        [
            (n.get("id"), n.get("ssid"), n.get("band"), n.get("enabled"))
            for n in main_candidates
        ],
        [
            (n.get("id"), n.get("ssid"), n.get("band"), n.get("enabled"))
            for n in guest_candidates
        ],
    )

    main_network = _select_best_network(main_candidates)
    guest_network = _select_best_network(guest_candidates)

    # We still create entities even when all bands are currently
    # disabled. The `available` property stays True and, once a QR has
    # been generated while the network was up, `async_image` keeps
    # serving those cached bytes so the user can continue to scan the
    # same code across on/off toggles without reloading the integration.

    if main_network:
        _LOGGER.info(
            "Creating main Wi-Fi QR entity: ssid=%s id=%s band=%s enabled=%s",
            main_network.get("ssid"),
            main_network.get("id"),
            main_network.get("band"),
            main_network.get("enabled"),
        )
        images.append(
            KeeneticQrWiFiImageEntity(coordinator, entry, main_network, "main")
        )

    if guest_network:
        _LOGGER.info(
            "Creating guest Wi-Fi QR entity: ssid=%s id=%s band=%s enabled=%s",
            guest_network.get("ssid"),
            guest_network.get("id"),
            guest_network.get("band"),
            guest_network.get("enabled"),
        )
        images.append(
            KeeneticQrWiFiImageEntity(coordinator, entry, guest_network, "guest")
        )

    async_add_entities(images)
    _LOGGER.debug("Added %d Wi-Fi QR image entities", len(images))


class KeeneticQrWiFiImageEntity(CoordinatorEntity[KeeneticCoordinator], ImageEntity):
    """Representation of a Keenetic Wi-Fi QR code image."""

    _attr_entity_registry_enabled_default = True
    _attr_has_entity_name = True
    _attr_content_type = "image/png"

    _unrecorded_attributes = frozenset(
        {
            "ssid",
            "interface_id",
            "enabled",
            "network_type",
            "band",
        }
    )

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        wifi_network: dict[str, Any],
        network_type: str,  # "main" or "guest"
    ) -> None:
        """Initialize the QR code image entity."""
        CoordinatorEntity.__init__(self, coordinator)
        ImageEntity.__init__(self, coordinator.hass)

        self._wifi_network = wifi_network
        self._entry = entry
        self._network_type = network_type
        self._image_bytes: bytes | None = None
        self._attr_device_info = self._get_device_info()
        self._attr_unique_id = f"{entry.entry_id}_wifi_qr_{network_type}"
        self._attr_image_last_updated = dt_util.utcnow()
        self._attr_translation_key = f"qr_wifi_{network_type}"
        self._attr_translation_placeholders = {
            "ssid": wifi_network.get("ssid", "Wi-Fi"),
        }

        _LOGGER.debug(
            "Created QR entity for %s network: %s",
            network_type,
            wifi_network.get("ssid"),
        )

    def _get_password_from_interfaces(self) -> str | None:
        """Get Wi-Fi password from interfaces data."""
        try:
            interfaces = self.coordinator.data.get("interfaces", {})
            interface_id = self._wifi_network.get("id")

            if interface_id and interface_id in interfaces:
                iface_data = interfaces[interface_id]
                auth = iface_data.get("authentication", {})
                if auth:
                    wpa_psk = auth.get("wpa-psk", {})
                    if wpa_psk and wpa_psk.get("psk"):
                        return wpa_psk.get("psk")

                if iface_data.get("password"):
                    return iface_data.get("password")

                wpa = iface_data.get("wpa", {})
                if wpa and wpa.get("psk"):
                    return wpa.get("psk")

            # Last-ditch: scan all interfaces for a matching SSID.
            for _iface_id, iface in interfaces.items():
                if (
                    isinstance(iface, dict)
                    and iface.get("ssid") == self._wifi_network.get("ssid")
                ):
                    auth = iface.get("authentication", {})
                    wpa_psk = auth.get("wpa-psk", {})
                    if wpa_psk and wpa_psk.get("psk"):
                        return wpa_psk.get("psk")
        except Exception as err:
            _LOGGER.debug("Could not get password for interface: %s", err)

        return None

    def _get_device_info(self) -> dict[str, Any]:
        """Get device info for the entity."""
        system_info = self.coordinator.data.get("system", {})
        host = getattr(self.coordinator.client, "_host", "unknown")

        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": "Keenetic Router",
            "manufacturer": "Keenetic",
            "model": system_info.get("model", "Router"),
            "sw_version": system_info.get("title", system_info.get("release")),
            "configuration_url": f"http://{host}",
        }

    async def async_image(self) -> bytes | None:
        """Return bytes of image.

        If the backing Wi-Fi network is currently disabled but we
        already produced a QR while it was up, serve those cached bytes
        as-is. This lets the user keep a scannable QR on screen when
        they turn the guest network off between visits — the cached QR
        still encodes the real SSID/PSK from the last time the network
        was live.
        """
        if (
            self._image_bytes is not None
            and not self._wifi_network.get("enabled")
        ):
            return self._image_bytes

        ssid = self._wifi_network.get("ssid")
        if not ssid:
            _LOGGER.warning(
                "QR %s: no SSID on wifi_network, cannot generate",
                self._network_type,
            )
            return None

        try:
            interface_id = self._wifi_network.get("id")
            wifi_passwords = self.coordinator.data.get("wifi_passwords", {})

            # 1. Exact interface id match (fast path)
            password = wifi_passwords.get(interface_id) if interface_id else None

            # 2. Fall back to any sibling AP with the same SSID. Keenetic
            #    stores passwords per AccessPoint id, so the 5 GHz radio
            #    may have no entry if only the 2.4 GHz one was fetched
            #    (or vice versa). Same SSID => same PSK in practice on
            #    dual-band networks.
            if not password:
                wifi_networks = self.coordinator.data.get("wifi", [])
                for net in wifi_networks:
                    if net.get("ssid") != ssid:
                        continue
                    sibling_id = net.get("id")
                    if sibling_id and wifi_passwords.get(sibling_id):
                        password = wifi_passwords[sibling_id]
                        _LOGGER.debug(
                            "QR %s: using PSK from sibling interface %s for SSID %s",
                            self._network_type, sibling_id, ssid,
                        )
                        break

            # 3. Last resort: scan raw interfaces dict.
            if not password:
                password = self._get_password_from_interfaces()

            if password:
                qr_string = f"WIFI:S:{ssid};T:WPA;P:{password};;"
                _LOGGER.debug(
                    "Generating QR code with password for %s network: %s",
                    self._network_type, ssid,
                )
            else:
                qr_string = f"WIFI:S:{ssid};T:nopass;;;"
                _LOGGER.debug(
                    "Generating QR code without password for %s network: %s",
                    self._network_type, ssid,
                )

            code = pyqrcode.create(qr_string)
            buffer = io.BytesIO()

            # Try PNG first (requires pypng), fall back to SVG.
            try:
                code.png(buffer, scale=10)
                self._attr_content_type = "image/png"
            except ImportError:
                _LOGGER.warning(
                    "pypng not installed, falling back to SVG for QR code. "
                    "Install pypng for PNG support: pip install pypng"
                )
                buffer = io.BytesIO()
                code.svg(buffer, scale=10, xmldecl=False, svgclass=None, lineclass=None)
                self._attr_content_type = "image/svg+xml"

            self._image_bytes = buffer.getvalue()
            return self._image_bytes

        except Exception as err:
            _LOGGER.error(
                "Error generating QR code for %s network %s: %s",
                self._network_type,
                self._wifi_network.get("ssid", "unknown"),
                err,
            )
            return None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if not self.coordinator.data:
            return
        wifi_networks = self.coordinator.data.get("wifi", [])

        # Gather every AP matching this entity's role, then let
        # _select_best_network pick enabled 5 GHz / enabled 2.4 GHz /
        # disabled fallback in that order. Same policy we used at setup.
        matching: list[dict[str, Any]] = []
        for net in wifi_networks:
            is_guest = _is_guest_wifi(net)
            if (self._network_type == "guest") != is_guest:
                continue
            matching.append(net)

        updated_network = _select_best_network(matching)
        if not updated_network:
            return

        old_ssid = self._wifi_network.get("ssid")
        new_ssid = updated_network.get("ssid")
        old_enabled = self._wifi_network.get("enabled")
        new_enabled = updated_network.get("enabled")
        old_id = self._wifi_network.get("id")
        new_id = updated_network.get("id")

        # Always refresh the tracked network so state attributes reflect
        # reality. But be careful with the image cache:
        #
        #   * Network just came UP (or is up and its SSID/id changed):
        #     invalidate so async_image regenerates a fresh QR with the
        #     new live credentials.
        #
        #   * Network is going/stays DOWN: keep the cached bytes
        #     untouched. async_image serves the last good QR verbatim,
        #     so a user who turned the guest network off between visits
        #     can still scan the existing code without reloading.
        should_invalidate = new_enabled and (
            not old_enabled
            or old_ssid != new_ssid
            or old_id != new_id
        )

        if old_ssid != new_ssid or old_enabled != new_enabled or old_id != new_id:
            _LOGGER.debug(
                "QR %s source changed (id: %s->%s, SSID: %s->%s, enabled: %s->%s), invalidate_cache=%s",
                self._network_type,
                old_id,
                new_id,
                old_ssid,
                new_ssid,
                old_enabled,
                new_enabled,
                should_invalidate,
            )
            self._wifi_network = updated_network
            if should_invalidate:
                self._image_bytes = None
                self._attr_image_last_updated = dt_util.utcnow()

        super()._handle_coordinator_update()

    @property
    def name(self) -> str:
        """Return the name of the entity."""
        if self._network_type == "main":
            return "Wi-Fi QR Code"
        return "Guest Wi-Fi QR Code"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra attributes of the image."""
        return {
            "ssid": self._wifi_network.get("ssid"),
            "interface_id": self._wifi_network.get("id"),
            "enabled": self._wifi_network.get("enabled", False),
            "network_type": self._network_type,
            "band": self._wifi_network.get("band"),
        }

    @property
    def available(self) -> bool:
        """Return if entity is available.

        We stay available even when the backing Wi-Fi network is
        currently disabled: the last generated QR keeps being served so
        the user can still scan it to rejoin once the network is turned
        back on.
        """
        return (
            super().available
            and self.coordinator.data is not None
            and self._wifi_network.get("ssid") is not None
        )
