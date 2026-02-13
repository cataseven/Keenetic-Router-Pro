"""Select entities for Keenetic Router Pro (client connection policy)."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import KeeneticClient
from .const import DOMAIN, DATA_CLIENT, DATA_COORDINATOR, CONF_TRACKED_CLIENTS
from .coordinator import KeeneticCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic Router Pro select entities from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: KeeneticCoordinator = data[DATA_COORDINATOR]
    client: KeeneticClient = data[DATA_CLIENT]

    entities: list[SelectEntity] = []

    # Policy listesini al
    policies = await client.async_get_policies()
    
    # Tracked client'lar için policy select entity'leri
    tracked_clients = entry.data.get(CONF_TRACKED_CLIENTS, [])
    
    for client_info in tracked_clients:
        if not isinstance(client_info, dict):
            continue
        
        mac = str(client_info.get("mac") or "").lower()
        if not mac:
            continue
        
        name = client_info.get("name") or mac.upper()
        entities.append(
            KeeneticClientPolicySelect(coordinator, entry, client, mac, name, policies)
        )

    if entities:
        async_add_entities(entities)


class KeeneticClientPolicySelect(CoordinatorEntity, SelectEntity):
    """Select entity for client connection policy."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:shield-account"

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        client: KeeneticClient,
        mac: str,
        name: str,
        policies: dict[str, str],
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._client = client
        self._mac = mac.lower()
        self._name = name
        self._policies = policies  # {"Policy0": "VPN", "Policy1": "Smart Home", ...}
        
        # Seçenekler: policy description'ları + default/deny
        self._id_to_display: dict[str, str] = {}  # policy_id -> display
        self._display_to_id: dict[str, str] = {}  # display -> policy_id
        
        # Default seçenek (policy atanmamış)
        self._id_to_display["__default__"] = "Default"
        self._display_to_id["Default"] = "__default__"
        
        # Deny seçeneği
        self._id_to_display["__deny__"] = "Deny (Blocked)"
        self._display_to_id["Deny (Blocked)"] = "__deny__"
        
        # Policy'leri ekle
        for policy_id, description in policies.items():
            self._id_to_display[policy_id] = description
            self._display_to_id[description] = policy_id

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_client_{self._mac}_policy"

    @property
    def name(self) -> str:
        return f"{self._name} Policy"

    @property
    def options(self) -> list[str]:
        # Sıralama: Default, Policy'ler (alfabetik), Deny
        policy_names = sorted(self._policies.values())
        return ["Default"] + policy_names + ["Deny (Blocked)"]

    @property
    def current_option(self) -> str | None:
        """Return current policy from host_policies data."""
        host_policies = self.coordinator.data.get("host_policies", {})
        
        host_info = host_policies.get(self._mac, {})
        access = host_info.get("access")
        policy_id = host_info.get("policy")
        
        # Deny durumu
        if access == "deny":
            return "Deny (Blocked)"
        
        # Policy atanmış
        if policy_id and policy_id in self._id_to_display:
            return self._id_to_display[policy_id]
        
        # Default (policy yok)
        return "Default"

    async def async_select_option(self, option: str) -> None:
        """Change the policy."""
        if option == "Default":
            await self._client.async_set_client_policy(self._mac, "default")
        elif option == "Deny (Blocked)":
            await self._client.async_set_client_policy(self._mac, "deny")
        else:
            # Policy ID'yi bul
            policy_id = self._display_to_id.get(option)
            if policy_id and policy_id not in ("__default__", "__deny__"):
                await self._client.async_set_client_policy(self._mac, policy_id)
        
        await self.coordinator.async_request_refresh()

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        host_policies = self.coordinator.data.get("host_policies", {})
        host_info = host_policies.get(self._mac, {})
        
        return {
            "mac": self._mac,
            "client_name": self._name,
            "policy_id": host_info.get("policy"),
            "access": host_info.get("access"),
            "available_policies": list(self._policies.values()),
        }

    @property
    def device_info(self) -> dict[str, Any]:
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": self._entry.title,
            "manufacturer": "Keenetic",
        }
