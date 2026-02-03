"""Config flow for Keenetic Router Pro."""

from __future__ import annotations

from typing import Any

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

from .api import KeeneticClient, KeeneticAuthError, KeeneticApiError
from .const import DOMAIN, DEFAULT_PORT, DEFAULT_SSL, CONF_TRACKED_CLIENTS


STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_SSL, default=DEFAULT_SSL): bool,
    }
)


async def _async_validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Router'a bağlanmayı ve temel info çekmeyi dene."""
    session = async_get_clientsession(hass)

    client = KeeneticClient(
        host=data[CONF_HOST],
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        port=data[CONF_PORT],
        ssl=data[CONF_SSL],
    )

    # Auth + basit system info testi
    await client.async_start(session)
    system = await client.async_get_system_info()

    # Bazı sistemlerde hostname farklı key'de olabilir, fallback host
    hostname = (
        system.get("hostname")
        or system.get("system", {}).get("hostname")
        or data[CONF_HOST]
    )

    return {
        "title": hostname,
        "client": client,
    }


class KeeneticRouterProConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Keenetic Router Pro config flow."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._user_input: dict[str, Any] = {}
        self._title: str = ""
        self._client: KeeneticClient | None = None
        self._available_clients: list[dict[str, Any]] = []

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """İlk adım: IP, kullanıcı adı, şifre al."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                info = await _async_validate_input(self.hass, user_input)
            except KeeneticAuthError:
                errors["base"] = "invalid_auth"
            except KeeneticApiError:
                errors["base"] = "cannot_connect"
            except Exception:  # pylint: disable=broad-except
                errors["base"] = "unknown"
            else:
                # Aynı host'tan bir tane olsun
                await self.async_set_unique_id(user_input[CONF_HOST])
                self._abort_if_unique_id_configured()

                # Bilgileri sakla ve client seçim adımına geç
                self._user_input = user_input
                self._title = info["title"]
                self._client = info["client"]

                # Client listesini çek
                try:
                    self._available_clients = await self._client.async_get_clients()
                except Exception:
                    self._available_clients = []

                # Eğer client yoksa direkt oluştur
                if not self._available_clients:
                    return self.async_create_entry(
                        title=self._title,
                        data={**self._user_input, CONF_TRACKED_CLIENTS: []},
                    )

                # Client varsa seçim adımına geç
                return await self.async_step_select_clients()

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_select_clients(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """İkinci adım: İzlenecek client'ları seç."""
        if user_input is not None:
            selected = user_input.get("tracked_clients", [])
            
            # Seçilen client bilgilerini kaydet (MAC ve IP)
            tracked_clients: list[dict[str, str]] = []
            for mac in selected:
                for client in self._available_clients:
                    client_mac = str(client.get("mac") or "").lower()
                    if client_mac == mac.lower():
                        ip = client.get("ip")
                        name = self._get_client_label(client)
                        tracked_clients.append({
                            "mac": client_mac,
                            "ip": str(ip) if ip else "",
                            "name": name,
                        })
                        break

            return self.async_create_entry(
                title=self._title,
                data={**self._user_input, CONF_TRACKED_CLIENTS: tracked_clients},
            )

        # Client seçeneklerini oluştur
        client_options_unsorted: dict[str, str] = {}
        seen_macs: set[str] = set()

        for client in self._available_clients:
            mac = str(client.get("mac") or "").lower()
            if not mac or mac in seen_macs:
                continue
            seen_macs.add(mac)

            label = self._get_client_label(client)
            ip = client.get("ip") or ""
            display = f"{label} ({ip})" if ip else label
            client_options_unsorted[mac] = display

        # Alfabetik sırala (label'a göre, case-insensitive)
        client_options = dict(
            sorted(client_options_unsorted.items(), key=lambda x: x[1].lower())
        )

        if not client_options:
            # Hiç geçerli client yoksa direkt oluştur
            return self.async_create_entry(
                title=self._title,
                data={**self._user_input, CONF_TRACKED_CLIENTS: []},
            )

        return self.async_show_form(
            step_id="select_clients",
            data_schema=vol.Schema(
                {
                    vol.Optional("tracked_clients", default=[]): vol.All(
                        cv.multi_select(client_options)
                    ),
                }
            ),
            description_placeholders={
                "client_count": str(len(client_options)),
            },
        )

    def _get_client_label(self, client: dict[str, Any]) -> str:
        """Client için görüntülenecek ismi al."""
        name_val = client.get("name")
        if isinstance(name_val, str) and name_val.strip():
            return name_val.strip()

        hostname = client.get("hostname")
        if isinstance(hostname, str) and hostname.strip():
            return hostname.strip()

        mac = client.get("mac") or "unknown"
        return str(mac).upper()

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Options flow handler."""
        return KeeneticOptionsFlow(config_entry)


# cv modülünü import et (multi_select için)
try:
    import homeassistant.helpers.config_validation as cv
except ImportError:
    # Fallback: manual multi_select
    class cv:
        @staticmethod
        def multi_select(options: dict[str, str]):
            """Multi-select validator."""
            def validator(value):
                if value is None:
                    return []
                if not isinstance(value, list):
                    value = [value]
                for v in value:
                    if v not in options:
                        raise vol.Invalid(f"Invalid option: {v}")
                return value
            return validator


class KeeneticOptionsFlow(config_entries.OptionsFlow):
    """Options flow for Keenetic Router Pro - allows editing tracked clients."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry = config_entry
        self._client: KeeneticClient | None = None
        self._available_clients: list[dict[str, Any]] = []

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            selected = user_input.get("tracked_clients", [])
            
            # Seçilen client bilgilerini kaydet
            tracked_clients: list[dict[str, str]] = []
            for mac in selected:
                for client in self._available_clients:
                    client_mac = str(client.get("mac") or "").lower()
                    if client_mac == mac.lower():
                        ip = client.get("ip")
                        name = self._get_client_label(client)
                        tracked_clients.append({
                            "mac": client_mac,
                            "ip": str(ip) if ip else "",
                            "name": name,
                        })
                        break

            # Config entry verisini güncelle
            new_data = dict(self._config_entry.data)
            new_data[CONF_TRACKED_CLIENTS] = tracked_clients
            self.hass.config_entries.async_update_entry(
                self._config_entry,
                data=new_data,
            )
            
            return self.async_create_entry(title="", data={})

        # Client'ı oluştur ve listeyi çek
        data = self._config_entry.data
        session = async_get_clientsession(self.hass)

        self._client = KeeneticClient(
            host=data.get("host") or data.get("ip"),
            username=data["username"],
            password=data["password"],
            port=int(data.get("port", DEFAULT_PORT)),
            ssl=bool(data.get("ssl", DEFAULT_SSL)),
        )

        try:
            await self._client.async_start(session)
            self._available_clients = await self._client.async_get_clients()
        except Exception:
            self._available_clients = []

        # Mevcut seçimleri al
        current_tracked = data.get(CONF_TRACKED_CLIENTS, [])
        current_macs = {
            c["mac"].lower() for c in current_tracked if isinstance(c, dict) and c.get("mac")
        }

        # Client seçeneklerini oluştur
        client_options_unsorted: dict[str, str] = {}
        seen_macs: set[str] = set()

        for client in self._available_clients:
            mac = str(client.get("mac") or "").lower()
            if not mac or mac in seen_macs:
                continue
            seen_macs.add(mac)

            label = self._get_client_label(client)
            ip = client.get("ip") or ""
            display = f"{label} ({ip})" if ip else label
            client_options_unsorted[mac] = display

        # Daha önce seçilmiş ama şu an listede olmayan client'ları da ekle
        for tracked in current_tracked:
            if isinstance(tracked, dict):
                mac = str(tracked.get("mac") or "").lower()
                if mac and mac not in client_options_unsorted:
                    name = tracked.get("name") or mac.upper()
                    ip = tracked.get("ip") or ""
                    display = f"{name} ({ip}) [offline]" if ip else f"{name} [offline]"
                    client_options_unsorted[mac] = display

        # Alfabetik sırala (label'a göre, case-insensitive)
        client_options = dict(
            sorted(client_options_unsorted.items(), key=lambda x: x[1].lower())
        )

        if not client_options:
            return self.async_abort(reason="no_clients")

        # Varsayılan olarak mevcut seçimleri işaretle
        default_selected = [mac for mac in current_macs if mac in client_options]

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        "tracked_clients",
                        default=default_selected,
                    ): cv.multi_select(client_options),
                }
            ),
            description_placeholders={
                "client_count": str(len(client_options)),
            },
        )

    def _get_client_label(self, client: dict[str, Any]) -> str:
        """Client için görüntülenecek ismi al."""
        name_val = client.get("name")
        if isinstance(name_val, str) and name_val.strip():
            return name_val.strip()

        hostname = client.get("hostname")
        if isinstance(hostname, str) and hostname.strip():
            return hostname.strip()

        mac = client.get("mac") or "unknown"
        return str(mac).upper()
