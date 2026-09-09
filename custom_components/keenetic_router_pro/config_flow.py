"""Config flow for Keenetic Router Pro."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import voluptuous as vol

from homeassistant import config_entries, data_entry_flow
from homeassistant.const import (
    CONF_HOST,
    CONF_PORT,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_SSL,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.service_info.ssdp import SsdpServiceInfo
from homeassistant.helpers.device_registry import format_mac

import logging

# Masked password input — uses HA's password selector so the field
# renders as dots in the UI on every config-flow step (initial setup,
# the SSDP-discovered confirm step, and any future re-auth /
# reconfigure flow). Without this the password is keyed in plaintext
# and is trivially captured by shoulder-surfing or a stray screenshot.
_PASSWORD_SELECTOR = selector.TextSelector(
    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
)

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
    CONF_LINK_STATE_FALLBACK,
    DEFAULT_LINK_STATE_FALLBACK,
)

_LOGGER = logging.getLogger(f"custom_components.{DOMAIN}.config_flow")


STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST, default="192.168.1.1"): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_USERNAME, default="admin"): str,
        vol.Required(CONF_PASSWORD): _PASSWORD_SELECTOR,
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
                # NOTE (#57): the SSDP-discovered host is offered only as the
                # *default* for the Host field (see ``default_host`` below) — it
                # is never force-substituted over what the user submitted.
                # Forcing it broke setups whose router really is at 192.168.1.1
                # but was discovered over IPv6: the user typing the IPv4 address
                # got silently overridden with an unreachable IPv6 host.

                # Defensive host normalisation — strip the most common
                # paste-mistakes users make when setting up KeenDNS
                # (issue #43). The Host field is documented as a plain
                # hostname or IP, but users naturally paste full URLs
                # like ``https://<name>.keenetic.pro/`` which would
                # otherwise produce the malformed
                # ``http://https://<name>.keenetic.pro:443/rci/...``
                # and a confusing 401. We do this *before* handing the
                # value to KeeneticClient so the downstream client and
                # the stored config entry both see the clean form.
                raw_host = str(user_input.get(CONF_HOST) or "").strip()
                for prefix in ("https://", "http://"):
                    if raw_host.lower().startswith(prefix):
                        raw_host = raw_host[len(prefix):]
                raw_host = raw_host.rstrip("/").strip()
                if raw_host:
                    user_input[CONF_HOST] = raw_host

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

                # Issue #64: async_start may have fallen back from Basic to
                # the challenge handshake (KeeneticOS 5.x rejects Basic on
                # the web port). Persist whichever scheme actually
                # authenticated, so later restarts go straight to it
                # instead of repeating the failing Basic attempt — and so
                # the checkbox in the UI reflects reality.
                user_input[CONF_USE_CHALLENGE_AUTH] = client.use_challenge_auth

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
            except data_entry_flow.AbortFlow:
                # HA's expected control-flow signal for "this device is
                # already configured" / "user reauth-completed" / similar.
                # Without this explicit re-raise, the generic Exception
                # handler below swallows the AbortFlow and reports it
                # as a scary "Unknown error" — most visibly when a user
                # tries to add the same router twice (e.g. once via LAN
                # and once via KeenDNS to test that auth path works).
                # Issue #43 follow-up.
                raise
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
                    vol.Required(CONF_PASSWORD): _PASSWORD_SELECTOR,
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

            # Issue #48: persist the link-state-fallback choice from
            # the initial setup form. Default is False — users with
            # devices on isolated sub-LANs opt-in here at setup time
            # (or later via the Options flow). Stored under
            # ``entry.data`` so it survives even if the user never
            # opens Options; the tracker resolves via the standard
            # options-overrides-data chain.
            link_state_fallback = bool(
                user_input.get(
                    CONF_LINK_STATE_FALLBACK, DEFAULT_LINK_STATE_FALLBACK
                )
            )

            _LOGGER.debug("Creating entry with title: %s", self._title)
            return self.async_create_entry(
                title=self._title,
                data={
                    **self._user_input,
                    CONF_TRACKED_CLIENTS: tracked_clients,
                    CONF_LINK_STATE_FALLBACK: link_state_fallback,
                },
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
                    # Issue #48: surface the cross-subnet fallback toggle
                    # here at initial setup so users with isolated
                    # sub-LANs (or routed LAN segments) don't have to
                    # learn about it from Options. Default OFF —
                    # see const.py for why.
                    vol.Optional(
                        CONF_LINK_STATE_FALLBACK,
                        default=DEFAULT_LINK_STATE_FALLBACK,
                    ): bool,
                }
            ),
            description_placeholders={
                "client_count": str(len(client_options)),
            },
        )

    # ----- Shared connection test helper -----
    async def _async_try_connect(
        self, candidate: dict[str, Any]
    ) -> str | None:
        """Verify credentials by attempting an actual API session.

        Returns ``None`` on success, otherwise an error key that
        matches one of the ``errors`` strings in the translations
        (``invalid_auth`` / ``cannot_connect`` / ``unknown``).

        Used by reauth and reconfigure to validate user input
        *before* persisting it to the config entry — we never want
        to overwrite a working entry's credentials with values that
        don't connect.
        """
        try:
            session = async_get_clientsession(self.hass)
            client = KeeneticClient(
                host=candidate[CONF_HOST],
                username=candidate[CONF_USERNAME],
                password=candidate[CONF_PASSWORD],
                port=candidate.get(CONF_PORT, DEFAULT_PORT),
                ssl=candidate.get(CONF_SSL, DEFAULT_SSL),
                use_challenge_auth=candidate.get(CONF_USE_CHALLENGE_AUTH, False),
            )
            await client.async_start(session)
            # Issue #64: record the scheme that actually authenticated —
            # async_start falls back from Basic to the challenge
            # handshake on KeeneticOS 5.x. Callers persist this so the
            # entry stops retrying a scheme the router refuses.
            candidate[CONF_USE_CHALLENGE_AUTH] = client.use_challenge_auth
            return None
        except KeeneticAuthError as err:
            _LOGGER.debug("Auth test failed: %s", err)
            return "invalid_auth"
        except KeeneticApiError as err:
            _LOGGER.debug("Connection test failed: %s", err)
            return "cannot_connect"
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Unexpected error during connection test")
            return "unknown"

    # ====================================================================
    # Reauth flow — triggered automatically by HA when the integration
    # raises ConfigEntryAuthFailed (typically because the router
    # password changed). Shows a focused form with just username +
    # password; host/port/ssl/challenge are preserved from the
    # existing entry, so the user only types what actually changed.
    # ====================================================================
    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> FlowResult:
        """Entry point — HA hands us the existing entry data."""
        self._reauth_entry_data = dict(entry_data)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Show the credential-update form and validate the new values."""
        errors: dict[str, str] = {}
        existing = self._reauth_entry_data

        if user_input is not None:
            # Build a full candidate dict by merging the new
            # credentials onto the existing entry data. That way the
            # connection test uses the right host/port/ssl/challenge
            # even though the user only re-entered username/password.
            candidate = {
                **existing,
                CONF_USERNAME: user_input[CONF_USERNAME],
                CONF_PASSWORD: user_input[CONF_PASSWORD],
            }
            err = await self._async_try_connect(candidate)
            if err is None:
                # Modern HA helper (≥ 2024.5): merges new data, triggers
                # a reload of the entry, and aborts this flow — replaces
                # the older `async_update_entry()` + `async_abort()`
                # pair which sometimes left users running with stale
                # credentials until they manually reloaded.
                entry = self.hass.config_entries.async_get_entry(
                    self.context["entry_id"]
                )
                if entry is None:
                    # Shouldn't happen in a reauth context, but bail
                    # gracefully rather than crash if HA's flow state
                    # has been garbage-collected.
                    return self.async_abort(reason="reauth_unknown_entry")
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_USE_CHALLENGE_AUTH: candidate[
                            CONF_USE_CHALLENGE_AUTH
                        ],
                    },
                )
            errors["base"] = err

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_USERNAME,
                        default=existing.get(CONF_USERNAME, "admin"),
                    ): str,
                    # No `default` on the password — pre-filling a
                    # password field is both a UX anti-pattern (user
                    # might submit unchanged value by accident) and a
                    # mild security smell (the masked value still gets
                    # serialised back to the frontend). User retypes.
                    vol.Required(CONF_PASSWORD): _PASSWORD_SELECTOR,
                }
            ),
            description_placeholders={
                "host": existing.get(CONF_HOST, ""),
            },
            errors=errors,
        )

    # ====================================================================
    # Reconfigure flow — triggered manually from the integration card
    # ("Configure" → "Reconfigure"). Lets the user change host / port /
    # SSL / challenge / credentials on an existing entry without
    # deleting it (which would lose entity history, automations
    # referencing entity_ids, dashboard cards, etc).
    # ====================================================================
    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Entry point — pull the entry being reconfigured from context."""
        entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        if entry is None:
            return self.async_abort(reason="reconfigure_unknown_entry")
        self._reconfigure_entry_data = dict(entry.data)
        return await self.async_step_reconfigure_confirm()

    async def async_step_reconfigure_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Show the full connection form pre-filled with current values."""
        errors: dict[str, str] = {}
        existing = self._reconfigure_entry_data

        if user_input is not None:
            # Reconfigure replaces the connection fields wholesale.
            # Tracked-client list, ping interval, and any other
            # options stay untouched because they live in
            # ``entry.options``, not ``entry.data``.
            candidate = {
                **existing,
                CONF_HOST: user_input[CONF_HOST],
                CONF_PORT: user_input[CONF_PORT],
                CONF_USERNAME: user_input[CONF_USERNAME],
                CONF_PASSWORD: user_input[CONF_PASSWORD],
                CONF_SSL: user_input[CONF_SSL],
                CONF_USE_CHALLENGE_AUTH: user_input.get(
                    CONF_USE_CHALLENGE_AUTH, False
                ),
            }
            err = await self._async_try_connect(candidate)
            if err is None:
                entry = self.hass.config_entries.async_get_entry(
                    self.context["entry_id"]
                )
                if entry is None:
                    return self.async_abort(reason="reconfigure_unknown_entry")
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={
                        CONF_HOST: user_input[CONF_HOST],
                        CONF_PORT: user_input[CONF_PORT],
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_SSL: user_input[CONF_SSL],
                        # Not user_input: _async_try_connect writes back
                        # the scheme that actually authenticated, which
                        # differs when Basic was refused and the client
                        # fell back to the challenge handshake (#64).
                        CONF_USE_CHALLENGE_AUTH: candidate[
                            CONF_USE_CHALLENGE_AUTH
                        ],
                    },
                )
            errors["base"] = err

        return self.async_show_form(
            step_id="reconfigure_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_HOST,
                        default=existing.get(CONF_HOST, "192.168.1.1"),
                    ): str,
                    vol.Optional(
                        CONF_PORT,
                        default=existing.get(CONF_PORT, DEFAULT_PORT),
                    ): int,
                    vol.Required(
                        CONF_USERNAME,
                        default=existing.get(CONF_USERNAME, "admin"),
                    ): str,
                    # No default on password — see rationale on reauth.
                    vol.Required(CONF_PASSWORD): _PASSWORD_SELECTOR,
                    vol.Optional(
                        CONF_SSL,
                        default=existing.get(CONF_SSL, DEFAULT_SSL),
                    ): bool,
                    vol.Optional(
                        CONF_USE_CHALLENGE_AUTH,
                        default=existing.get(CONF_USE_CHALLENGE_AUTH, False),
                    ): bool,
                }
            ),
            errors=errors,
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
            # Persist BOTH the ping interval AND the link-state-fallback
            # toggle (issue #48). Both live in entry.options so a change
            # triggers an integration reload without touching the user's
            # tracked-client list.
            link_state_fallback = bool(
                user_input.get(CONF_LINK_STATE_FALLBACK, DEFAULT_LINK_STATE_FALLBACK)
            )
            return self.async_create_entry(
                title="",
                data={
                    CONF_PING_INTERVAL: ping_interval,
                    CONF_LINK_STATE_FALLBACK: link_state_fallback,
                },
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

        # Current link-state-fallback setting. Resolved via the same
        # options-overrides-data chain as ping_interval, so the value
        # chosen during initial setup shows up as the default when the
        # user opens Options for the first time.
        current_link_state_fallback = self._config_entry.options.get(
            CONF_LINK_STATE_FALLBACK,
            self._config_entry.data.get(
                CONF_LINK_STATE_FALLBACK, DEFAULT_LINK_STATE_FALLBACK
            ),
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
                    vol.Optional(
                        CONF_LINK_STATE_FALLBACK,
                        default=current_link_state_fallback,
                    ): bool,
                }
            ),
            description_placeholders={
                "client_count": str(len(client_options)),
            },
        )