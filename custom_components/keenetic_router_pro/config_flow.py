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
from .const import (
    DOMAIN,
    DEFAULT_PORT,
    DEFAULT_SSL,
    CONF_TRACKED_CLIENTS,
    CONF_USE_CHALLENGE_AUTH,
    CONF_PING_INTERVAL,
    DEFAULT_PING_INTERVAL,
    MIN_PING_INTERVAL,
    MAX_PING_INTERVAL,
)

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
        self._available_clients: list[dict[str, Any]] = []
        self._user_input: dict[str, Any] = {}
        self._title: str = ""
        self._client: KeeneticClient | None = None

    async def async_step_ssdp(self, discovery_info: SsdpServiceInfo) -> FlowResult:
        """Handle a discovered Keenetic router via SSDP."""
        _LOGGER.debug("SSDP discovery received: %s", discovery_info)
        
        hostname = urlparse(discovery_info.ssdp_location).hostname
        if not hostname:
            _LOGGER.debug("No hostname in SSDP discovery, aborting")
            return self.async_abort(reason="no_host")

        current_entries = self._async_current_entries()
        _LOGGER.debug("Checking %d existing entries for host %s", len(current_entries), hostname)
        
        for entry in current_entries:
            entry_host = entry.data.get(CONF_HOST)
            _LOGGER.debug("Entry %s has host: %s", entry.title, entry_host)
            if entry_host == hostname:
                _LOGGER.debug("Router at %s is already configured as '%s', skipping SSDP", 
                            hostname, entry.title)
                return self.async_abort(reason="already_configured")
        
        self._discovered_host = hostname
        self._discovered_name = discovery_info.upnp.get("friendlyName", "Keenetic Router")

        self.context["title_placeholders"] = {
            "name": self._discovered_name,
            "host": hostname
        }

        _LOGGER.debug("Discovered new Keenetic router via SSDP: %s at %s", self._discovered_name, hostname)
        
        return await self.async_step_user()

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        
        _LOGGER.debug("Step user called with input: %s", user_input)

        if user_input is not None:
            try:
                if self._discovered_host and user_input.get(CONF_HOST) == "192.168.1.1":
                    user_input[CONF_HOST] = self._discovered_host
                    _LOGGER.debug("Using discovered host: %s", user_input[CONF_HOST])

                session = async_get_clientsession(self.hass)
                client = KeeneticClient(
                    host=user_input[CONF_HOST],
                    username=user_input[CONF_USERNAME],
                    password=user_input[CONF_PASSWORD],
                    port=user_input[CONF_PORT],
                    ssl=user_input[CONF_SSL],
                    use_challenge_auth=user_input.get(CONF_USE_CHALLENGE_AUTH, False),
                )
                
                _LOGGER.debug("Attempting to connect to router at %s:%s", 
                             user_input[CONF_HOST], user_input[CONF_PORT])
                
                await client.async_start(session)
                system_info = await client.async_get_system_info()   
                interfaces = await client.async_get_interfaces()
                mac = None
                if isinstance(interfaces, dict):
                    for iface_id, iface_data in interfaces.items():
                        if isinstance(iface_data, dict):
                            if iface_data.get("type") == "Bridge" or "Bridge0" in iface_id:
                                mac = iface_data.get("mac")
                                if mac:
                                    _LOGGER.debug("Found Bridge MAC: %s from %s", mac, iface_id)
                                    break
                    
                    if not mac:
                        for iface_id, iface_data in interfaces.items():
                            if isinstance(iface_data, dict):
                                mac = iface_data.get("mac")
                                if mac and mac != "00:00:00:00:00:00":
                                    _LOGGER.debug("Found interface MAC: %s from %s", mac, iface_id)
                                    break

                vendor = system_info.get("vendor", "Keenetic")
                device = system_info.get("device", system_info.get("model", "Router"))
                
                if mac:
                    formatted_mac = format_mac(mac).replace(":", "")
                    unique_suffix = formatted_mac[-8:] if len(formatted_mac) >= 8 else formatted_mac
                    unique_id = f"{vendor} {device} {unique_suffix}"
                else:
                    hostname = system_info.get("hostname", user_input[CONF_HOST])
                    unique_id = f"{vendor} {device} {hostname}"
                
                await self.async_set_unique_id(unique_id)
                self._abort_if_unique_id_configured()

                self._user_input = user_input
                self._title = f"{vendor} {device}"
                self._client = client
                
                try:
                    available_clients = await client.async_get_clients()
                    _LOGGER.debug("Found %d clients", len(available_clients) if available_clients else 0)
                    
                    if available_clients:
                        self._available_clients = []
                        for client_info in available_clients:
                            if client_info.get("mac"):
                                self._available_clients.append({
                                    "mac": client_info["mac"].lower(),
                                    "ip": client_info.get("ip", ""),
                                    "name": client_info.get("name") or client_info.get("hostname", ""),
                                })
                        
                        return await self.async_step_select_clients()
                    else:
                        _LOGGER.debug("No clients found, creating entry directly")
                        return self.async_create_entry(
                            title=self._title,
                            data={**user_input, CONF_TRACKED_CLIENTS: []},
                        )
                        
                except Exception as e:
                    _LOGGER.warning("Could not fetch clients: %s", e)
                    return self.async_create_entry(
                        title=self._title,
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

        default_host = self._discovered_host or "192.168.1.1"
        
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
        _LOGGER.debug("Step select_clients called with input: %s", user_input)
        
        if user_input is not None:
            selected_macs = user_input.get("tracked_clients", [])
            _LOGGER.debug("Selected MACs: %s", selected_macs)
            
            # Filter selected clients
            tracked_clients = [
                client for client in self._available_clients
                if client["mac"] in selected_macs
            ]
            
            _LOGGER.debug("Creating entry with title: %s", self._title)
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
        
        _LOGGER.debug("Showing client selection form with %d options", len(client_options))
        
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
        _LOGGER.debug("Options flow init called with input: %s", user_input)
        
        if user_input is not None:
            selected_macs = user_input.get("tracked_clients", [])

            # Validate / clamp ping interval
            ping_interval_raw = user_input.get(CONF_PING_INTERVAL, DEFAULT_PING_INTERVAL)
            try:
                ping_interval = int(ping_interval_raw)
            except (TypeError, ValueError):
                ping_interval = DEFAULT_PING_INTERVAL
            if ping_interval < MIN_PING_INTERVAL:
                ping_interval = MIN_PING_INTERVAL
            elif ping_interval > MAX_PING_INTERVAL:
                ping_interval = MAX_PING_INTERVAL
            
            # Convert selected MAC strings back to dict format
            # First, build a lookup from available clients + previously tracked
            mac_lookup: dict[str, dict[str, str]] = {}
            for c in self._available_clients:
                if isinstance(c, dict) and c.get("mac"):
                    mac_lookup[c["mac"].lower()] = c
            # Also include previously tracked clients (for offline devices)
            for c in self._config_entry.data.get(CONF_TRACKED_CLIENTS, []):
                if isinstance(c, dict) and c.get("mac"):
                    mac_lower = c["mac"].lower()
                    if mac_lower not in mac_lookup:
                        mac_lookup[mac_lower] = c
            
            tracked_clients = []
            for mac in selected_macs:
                mac_lower = mac.lower()
                if mac_lower in mac_lookup:
                    tracked_clients.append(mac_lookup[mac_lower])
                else:
                    # Fallback: create a minimal dict
                    tracked_clients.append({"mac": mac_lower, "ip": "", "name": ""})
            
            # Update configuration
            new_data = dict(self._config_entry.data)
            new_data[CONF_TRACKED_CLIENTS] = tracked_clients
            self.hass.config_entries.async_update_entry(
                self._config_entry,
                data=new_data,
            )
            _LOGGER.debug("Updated configuration with new tracked clients: %s", tracked_clients)
            return self.async_create_entry(
                title="",
                data={CONF_PING_INTERVAL: ping_interval},
            )
        
        # Get current tracked clients
        current_tracked = self._config_entry.data.get(CONF_TRACKED_CLIENTS, [])
        current_macs = {c["mac"] for c in current_tracked if isinstance(c, dict) and c.get("mac")}
        _LOGGER.debug("Current tracked MACs: %s", current_macs)
        
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
            _LOGGER.debug("Found %d clients from router", len(available_clients) if available_clients else 0)
            
            # Prepare client options
            client_options = {}
            for client_info in available_clients:
                if client_info.get("mac"):
                    mac = client_info["mac"].lower()
                    label = client_info.get("name") or client_info.get("hostname") or mac.upper()
                    if client_info.get("ip"):
                        label = f"{label} ({client_info['ip']})"
                    client_options[mac] = label
                    # Store full client info for dict conversion later
                    self._available_clients.append({
                        "mac": mac,
                        "ip": client_info.get("ip", ""),
                        "name": client_info.get("name") or client_info.get("hostname", ""),
                    })
            
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
            _LOGGER.debug("Prepared %d client options", len(client_options))
            
        except Exception as e:
            _LOGGER.error("Could not fetch clients for options: %s", e)
            # Use only previously tracked clients
            client_options = {
                tracked["mac"]: tracked.get("name", tracked["mac"].upper())
                for tracked in current_tracked
                if isinstance(tracked, dict) and tracked.get("mac")
            }
        
        # Current ping interval (options > data > default)
        current_ping_interval = self._config_entry.options.get(
            CONF_PING_INTERVAL,
            self._config_entry.data.get(CONF_PING_INTERVAL, DEFAULT_PING_INTERVAL),
        )

        # Show form
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional("tracked_clients", default=list(current_macs)): cv.multi_select(client_options),
                    vol.Optional(
                        CONF_PING_INTERVAL,
                        default=current_ping_interval,
                    ): vol.All(vol.Coerce(int), vol.Range(min=MIN_PING_INTERVAL, max=MAX_PING_INTERVAL)),
                }
            ),
            description_placeholders={
                "client_count": str(len(client_options)),
            },
        )