"""Keenetic Router Pro integration root."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers import config_validation as cv

from .api import KeeneticClient
from .const import (
    DOMAIN,
    DEFAULT_PORT,
    DEFAULT_SSL,
    DATA_CLIENT,
    DATA_COORDINATOR,
    DATA_PING_COORDINATOR,
    CONF_TRACKED_CLIENTS,
    EVENT_NEW_DEVICE,
)
from .coordinator import KeeneticCoordinator, KeeneticPingCoordinator

_LOGGER = logging.getLogger(__name__)

# Bu entegrasyon sadece config entry ile kurulabilir
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

# Hangi platformlar yüklenecek
PLATFORMS: list[str] = ["sensor", "switch", "device_tracker", "button", "binary_sensor", "select"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Config entry oluşturulduğunda çalışır."""
    data: dict[str, Any] = dict(entry.data)

    host: str = data.get("host") or data.get("ip")  # yanlış yazılırsa diye fallback
    username: str = data["username"]
    password: str = data["password"]
    port: int = int(data.get("port", DEFAULT_PORT))
    use_ssl: bool = bool(data.get("ssl", DEFAULT_SSL))

    session = async_get_clientsession(hass)

    client = KeeneticClient(
        host=host,
        username=username,
        password=password,
        port=port,
        ssl=use_ssl,
    )
    await client.async_start(session)

    coordinator = KeeneticCoordinator(hass, client)
    await coordinator.async_config_entry_first_refresh()

    tracked_clients = data.get(CONF_TRACKED_CLIENTS, [])

    ping_coordinator = KeeneticPingCoordinator(hass, client, tracked_clients)
    
    # Eğer tracked client varsa ping coordinator'ı başlat
    if tracked_clients:
        await ping_coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        DATA_CLIENT: client,
        DATA_COORDINATOR: coordinator,
        DATA_PING_COORDINATOR: ping_coordinator,
    }

    @callback
    def _async_handle_new_device() -> None:
        """Yeni cihaz bağlandığında event tetikle."""
        new_clients = coordinator.data.get("new_clients", set())
        clients = coordinator.data.get("clients", [])
        
        for mac in new_clients:
            # Client bilgilerini bul
            client_info = None
            for c in clients:
                if str(c.get("mac") or "").lower() == mac:
                    client_info = c
                    break
            
            if client_info:
                name = client_info.get("name") or client_info.get("hostname") or mac.upper()
                ip = client_info.get("ip")
                
                _LOGGER.info("New device connected: %s (%s) - %s", name, mac, ip)
                
                hass.bus.async_fire(
                    EVENT_NEW_DEVICE,
                    {
                        "mac": mac,
                        "name": name,
                        "ip": ip,
                        "hostname": client_info.get("hostname"),
                        "interface": client_info.get("interface"),
                        "ssid": client_info.get("ssid"),
                    },
                )

    coordinator.async_add_listener(_async_handle_new_device)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    entry.async_on_unload(entry.add_update_listener(async_update_listener))
    
    return True


async def async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Config entry güncellendiğinde çağrılır (options flow sonrası)."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Config entry silinir veya devre dışı bırakılırken çalışır."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unload_ok:
        return False

    entry_data = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if entry_data:
        client: KeeneticClient = entry_data.get(DATA_CLIENT)

    if not hass.data.get(DOMAIN):
        hass.data.pop(DOMAIN, None)

    return True
