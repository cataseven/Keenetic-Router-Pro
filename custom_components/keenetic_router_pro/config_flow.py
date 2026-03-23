"""Config flow for Keenetic Router Pro."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import (
    CONF_HOST,
    CONF_PORT,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_SSL,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.service_info.ssdp import SsdpServiceInfo
from homeassistant.helpers.device_registry import format_mac

import logging

from .api import KeeneticClient, KeeneticAuthError, KeeneticApiError
from .const import DOMAIN, DEFAULT_PORT, DEFAULT_SSL, CONF_TRACKED_CLIENTS, CONF_USE_CHALLENGE_AUTH

_LOGGER = logging.getLogger(f"custom_components.{DOMAIN}.config_flow")


STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST, default="192.168.1.1"): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_USERNAME, default="admin"): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_SSL, default=DEFAULT_SSL): bool,
        vol.Optional(CONF_USE_CHALLENGE_AUTH, default=False): bool,
    }
)


class KeeneticRouterProConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Keenetic Router Pro config flow."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._discovered_host: str | None = None
        self._discovered_name: str | None = None

    async def async_step_ssdp(self, discovery_info: SsdpServiceInfo) -> FlowResult:
        """Handle a discovered Keenetic router via SSDP."""
        # Extract hostname from SSDP location URL
        hostname = urlparse(discovery_info.ssdp_location).hostname
        if not hostname:
            return self.async_abort(reason="no_host")

        # Store discovered host for later use
        self._discovered_host = hostname
        self._discovered_name = discovery_info.upnp.get("friendlyName", "Keenetic Router")

        # Set context title for UI display
        self.context["title_placeholders"] = {
            "name": self._discovered_name,
            "host": hostname
        }

        _LOGGER.debug("Discovered Keenetic router via SSDP: %s at %s", self._discovered_name, hostname)

        # Proceed to user step with pre-filled host
        return await self.async_step_user()

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                # Use discovered host if available and not overridden
                if self._discovered_host and user_input.get(CONF_HOST) == "192.168.1.1":
                    user_input[CONF_HOST] = self._discovered_host
                
                # Create API client and test connection
                session = async_get_clientsession(self.hass)
                client = KeeneticClient(
                    host=user_input[CONF_HOST],
                    username=user_input[CONF_USERNAME],
                    password=user_input[CONF_PASSWORD],
                    port=user_input[CONF_PORT],
                    ssl=user_input[CONF_SSL],
                    use_challenge_auth=user_input.get(CONF_USE_CHALLENGE_AUTH, False),
                )
                
                await client.async_start(session)
                
                # Get system info and interfaces to create unique ID
                system_info = await client.async_get_system_info()
                interfaces = await client.async_get_interfaces()
                
                # Find MAC address (similar to the working integration)
                mac = None
                if isinstance(interfaces, dict):
                    for iface_id, iface_data in interfaces.items():
                        if isinstance(iface_data, dict):
                            if iface_data.get("type") == "Bridge" or "Bridge0" in iface_id:
                                mac = iface_data.get("mac")
                                if mac:
                                    break
                    
                    if not mac:
                        for iface_id, iface_data in interfaces.items():
                            if isinstance(iface_data, dict):
                                mac = iface_data.get("mac")
                                if mac and mac != "00:00:00:00:00:00":
                                    break
                
                # Create unique ID similar to the working integration
                vendor = system_info.get("vendor", "Keenetic")
                device = system_info.get("device", system_info.get("model", "Router"))
                
                if mac:
                    # Format MAC and take last 8 chars (like the working integration)
                    formatted_mac = format_mac(mac).replace(":", "")
                    unique_suffix = formatted_mac[-8:] if len(formatted_mac) >= 8 else formatted_mac
                    unique_id = f"{vendor} {device} {unique_suffix}"
                else:
                    # Fallback to hostname
                    hostname = system_info.get("hostname", user_input[CONF_HOST])
                    unique_id = f"{vendor} {device} {hostname}"
                
                _LOGGER.debug("Generated unique ID: %s", unique_id)
                
                # Check if already configured
                await self.async_set_unique_id(unique_id)
                self._abort_if_unique_id_configured()
                
                # Get title
                title = f"{vendor} {device}"
                
                # Get clients for selection
                try:
                    available_clients = await client.async_get_clients()
                    
                    # Tracked clients selection
                    if available_clients:
                        tracked_clients = []
                        for client_info in available_clients:
                            if client_info.get("mac"):
                                tracked_clients.append({
                                    "mac": client_info["mac"].lower(),
                                    "ip": client_info.get("ip", ""),
                                    "name": client_info.get("name") or client_info.get("hostname", ""),
                                })
                        
                        # Store client info for next step
                        self._available_clients = tracked_clients
                        self._user_input = user_input
                        self._title = title
                        self._client = client
                        
                        return await self.async_step_select_clients()
                    else:
                        # No clients found, create entry directly
                        return self.async_create_entry(
                            title=title,
                            data={**user_input, CONF_TRACKED_CLIENTS: []},
                        )
                        
                except Exception as e:
                    _LOGGER.warning("Could not fetch clients: %s", e)
                    return self.async_create_entry(
                        title=title,
                        data={**user_input, CONF_TRACKED_CLIENTS: []},
                    )

            except KeeneticAuthError as err:
                _LOGGER.error("Authentication failed: %s", err)
                errors["base"] = "invalid_auth"
            except KeeneticApiError as err:
                _LOGGER.error("API/connection error: %s", err)
                errors["base"] = "cannot_connect"
            except Exception as err:
                _LOGGER.exception("Unexpected error during setup: %s", err)
                errors["base"] = "unknown"

        # Prepare default values
        default_host = self._discovered_host or "192.168.1.1"
        
        # Show form
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_HOST, default=default_host): str,
                    vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
                    vol.Required(CONF_USERNAME, default="admin"): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Optional(CONF_SSL, default=DEFAULT_SSL): bool,
                    vol.Optional(CONF_USE_CHALLENGE_AUTH, default=False): bool,
                }
            ),
            errors=errors,
            description_placeholders={
                "name": self._discovered_name or "Keenetic Router"
            } if self._discovered_name else None,
        )

    async def async_step_select_clients(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Select clients to track."""
        if user_input is not None:
            selected_macs = user_input.get("tracked_clients", [])
            
            # Filter selected clients
            tracked_clients = [
                client for client in self._available_clients
                if client["mac"] in selected_macs
            ]
            
            return self.async_create_entry(
                title=self._title,
                data={**self._user_input, CONF_TRACKED_CLIENTS: tracked_clients},
            )
        
        # Prepare client options
        client_options = {}
        for client in self._available_clients:
            label = client.get("name") or client.get("ip") or client["mac"].upper()
            if client.get("ip"):
                label = f"{label} ({client['ip']})"
            client_options[client["mac"]] = label
        
        # Sort alphabetically
        client_options = dict(sorted(client_options.items(), key=lambda x: x[1].lower()))
        
        return self.async_show_form(
            step_id="select_clients",
            data_schema=vol.Schema(
                {
                    vol.Optional("tracked_clients", default=[]): cv.multi_select(client_options),
                }
            ),
            description_placeholders={
                "client_count": str(len(client_options)),
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Options flow handler."""
        return KeeneticOptionsFlow(config_entry)


# Import cv for multi_select
import homeassistant.helpers.config_validation as cv


class KeeneticOptionsFlow(config_entries.OptionsFlow):
    """Options flow for Keenetic Router Pro."""
    
    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry = config_entry
        self._client = None
        self._available_clients = []
    
    async def async_step_init(self, user_input=None):
        """Manage options."""
        if user_input is not None:
            # Update configuration
            new_data = dict(self._config_entry.data)
            new_data[CONF_TRACKED_CLIENTS] = user_input.get("tracked_clients", [])
            self.hass.config_entries.async_update_entry(
                self._config_entry,
                data=new_data,
            )
            return self.async_create_entry(title="", data={})
        
        # Get current tracked clients
        current_tracked = self._config_entry.data.get(CONF_TRACKED_CLIENTS, [])
        current_macs = {c["mac"] for c in current_tracked if isinstance(c, dict) and c.get("mac")}
        
        # Try to get current clients from router
        try:
            # Initialize client
            data = self._config_entry.data
            session = async_get_clientsession(self.hass)
            client = KeeneticClient(
                host=data[CONF_HOST],
                username=data[CONF_USERNAME],
                password=data[CONF_PASSWORD],
                port=data.get(CONF_PORT, DEFAULT_PORT),
                ssl=data.get(CONF_SSL, DEFAULT_SSL),
                use_challenge_auth=data.get(CONF_USE_CHALLENGE_AUTH, False),
            )
            await client.async_start(session)
            available_clients = await client.async_get_clients()
            
            # Prepare client options
            client_options = {}
            for client_info in available_clients:
                if client_info.get("mac"):
                    mac = client_info["mac"].lower()
                    label = client_info.get("name") or client_info.get("hostname") or mac.upper()
                    if client_info.get("ip"):
                        label = f"{label} ({client_info['ip']})"
                    client_options[mac] = label
            
            # Add offline clients that were previously tracked
            for tracked in current_tracked:
                if isinstance(tracked, dict) and tracked.get("mac"):
                    mac = tracked["mac"].lower()
                    if mac not in client_options:
                        name = tracked.get("name", mac.upper())
                        ip = tracked.get("ip", "")
                        label = f"{name} ({ip}) [offline]" if ip else f"{name} [offline]"
                        client_options[mac] = label
            
            # Sort options
            client_options = dict(sorted(client_options.items(), key=lambda x: x[1].lower()))
            
        except Exception as e:
            _LOGGER.error("Could not fetch clients for options: %s", e)
            # Use only previously tracked clients
            client_options = {
                tracked["mac"]: tracked.get("name", tracked["mac"].upper())
                for tracked in current_tracked
                if isinstance(tracked, dict) and tracked.get("mac")
            }
        
        # Show form
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional("tracked_clients", default=list(current_macs)): cv.multi_select(client_options),
                }
            ),
        )