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


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic image entities."""
    coordinator: KeeneticCoordinator = hass.data[DOMAIN][entry.entry_id][DATA_COORDINATOR]
    images: list[ImageEntity] = []

    # Get WiFi networks from coordinator data
    wifi_networks = coordinator.data.get("wifi", [])
    
    if not wifi_networks:
        _LOGGER.debug("No WiFi networks found, skipping QR images")
        async_add_entities(images)
        return

    mesh_nodes = coordinator.data.get("mesh_nodes", [])
    mesh_ips = {node.get("ip") for node in mesh_nodes if node.get("ip")}
    
    _LOGGER.debug("Found mesh nodes IPs: %s", mesh_ips)

    main_network = None
    guest_network = None
    
    for wifi_network in wifi_networks:
        ssid = wifi_network.get("ssid")
        if not ssid:
            continue
            
        interface_id = wifi_network.get("id", "")
        description = wifi_network.get("description", "").lower()
        is_mesh = False

        for mesh_ip in mesh_ips:
            if mesh_ip in interface_id or mesh_ip in str(wifi_network):
                is_mesh = True
                break
        
        if is_mesh:
            _LOGGER.debug("Skipping mesh node interface: %s", interface_id)
            continue

        is_guest = (
            "guest" in ssid.lower() or 
            "guest" in description or
            "AccessPoint1" in interface_id  
        )
        
        if is_guest:
            if guest_network is None:
                guest_network = wifi_network
                _LOGGER.debug("Found guest network: %s (SSID: %s)", interface_id, ssid)
        else:
            if main_network is None:
                main_network = wifi_network
                _LOGGER.debug("Found main network: %s (SSID: %s)", interface_id, ssid)

    if main_network:
        _LOGGER.info("Creating QR code for main Wi-Fi network: %s", main_network.get("ssid"))
        images.append(
            KeeneticQrWiFiImageEntity(
                coordinator,
                entry,
                main_network,
                "main",
            )
        )
    else:
        _LOGGER.warning("No main Wi-Fi network found")

    if guest_network:
        _LOGGER.info("Creating QR code for guest Wi-Fi network: %s", guest_network.get("ssid"))
        images.append(
            KeeneticQrWiFiImageEntity(
                coordinator,
                entry,
                guest_network,
                "guest",
            )
        )
    else:
        _LOGGER.debug("No guest Wi-Fi network found")

    async_add_entities(images)
    _LOGGER.debug("Added %d QR image entities (main: %s, guest: %s)", 
                  len(images), 
                  main_network is not None,
                  guest_network is not None)


class KeeneticQrWiFiImageEntity(CoordinatorEntity[KeeneticCoordinator], ImageEntity):
    """Representation of a Keenetic Wi-Fi QR code image."""

    _attr_entity_registry_enabled_default = False
    _attr_has_entity_name = True
    _attr_content_type = "image/png"

    # These attributes won't be recorded in history
    _unrecorded_attributes = frozenset(
        {
            "ssid",
            "interface_id",
            "enabled",
            "network_type",
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
        self._password = self._get_password_from_interfaces()
        self._attr_device_info = self._get_device_info()
        self._attr_unique_id = f"{entry.entry_id}_wifi_qr_{network_type}"
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

                for iface_id, iface in interfaces.items():
                    if isinstance(iface, dict) and iface.get("ssid") == self._wifi_network.get("ssid"):
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
        host = getattr(self.coordinator.client, '_host', 'unknown')
        
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": "Keenetic Router",
            "manufacturer": "Keenetic",
            "model": system_info.get("model", "Router"),
            "sw_version": system_info.get("title", system_info.get("release")),
            "configuration_url": f"http://{host}",
        }

    async def async_image(self) -> bytes | None:
        """Return bytes of image."""
        ssid = self._wifi_network.get("ssid")
        if not ssid:
            return None

        try:
            password = self._get_password_from_interfaces()
            if password:
                qr_string = f"WIFI:S:{ssid};T:WPA;P:{password};;"
                _LOGGER.debug("Generating QR code with password for %s network: %s", 
                             self._network_type, ssid)
            else:
                qr_string = f"WIFI:S:{ssid};T:nopass;;;"
                _LOGGER.debug("Generating QR code without password for %s network: %s", 
                             self._network_type, ssid)

            code = pyqrcode.create(qr_string)
            buffer = io.BytesIO()
            code.png(buffer, scale=10)
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
        current_ssid = self._wifi_network.get("ssid")
        updated_network = None
        
        for net in wifi_networks:
            if net.get("ssid") != current_ssid:
                continue
                
            is_guest = self._is_guest_network(net)
            if (self._network_type == "guest" and is_guest) or \
               (self._network_type == "main" and not is_guest):
                updated_network = net
                break
        
        if not updated_network:
            return

        old_ssid = self._wifi_network.get("ssid")
        new_ssid = updated_network.get("ssid")
        old_enabled = self._wifi_network.get("enabled")
        new_enabled = updated_network.get("enabled")
        
        if old_ssid != new_ssid or old_enabled != new_enabled:
            _LOGGER.debug(
                "%s network settings changed (SSID: %s->%s, enabled: %s->%s), regenerating QR code",
                self._network_type.capitalize(),
                old_ssid,
                new_ssid,
                old_enabled,
                new_enabled,
            )
            self._wifi_network = updated_network
            self._image_bytes = None  
            self._attr_image_last_updated = dt_util.utcnow()

        super()._handle_coordinator_update()

    def _is_guest_network(self, network: dict[str, Any]) -> bool:
        """Check if network is a guest network."""
        ssid = network.get("ssid", "").lower()
        description = network.get("description", "").lower()
        interface_id = network.get("id", "").lower()
        
        return (
            "guest" in ssid or
            "guest" in description or
            "accesspoint1" in interface_id
        )
    
    @property
    def name(self) -> str:
        """Return the name of the entity."""
        if self._network_type == "main":
            return "Wi-Fi QR Code"
        else:
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
        """Return if entity is available."""
        return (
            super().available
            and self.coordinator.data is not None
            and self._wifi_network.get("ssid") is not None
        )