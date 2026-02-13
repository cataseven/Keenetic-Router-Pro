"""Switches for Keenetic Router Pro (Wi-Fi + WireGuard on/off)."""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import KeeneticClient
from .const import DOMAIN, DATA_CLIENT, DATA_COORDINATOR
from .coordinator import KeeneticCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic Router Pro switches from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: KeeneticCoordinator = data[DATA_COORDINATOR]
    client: KeeneticClient = data[DATA_CLIENT]

    entities: list[SwitchEntity] = []

    # Wi-Fi interface switch'leri
    for net in coordinator.data.get("wifi", []):
        iface_id = net.get("id") or net.get("name")
        if not iface_id:
            continue

        display_name = net.get("name") or net.get("ssid") or iface_id

        entities.append(
            KeeneticWifiSwitch(
                coordinator=coordinator,
                entry=entry,
                client=client,
                interface_id=iface_id,
                display_name=display_name,
            )
        )

    vpn_profiles = coordinator.data.get("vpn_tunnels", {}).get("profiles", {}) or {}
    for iface_id, profile in vpn_profiles.items():
        entities.append(
            KeeneticVpnSwitch(
                coordinator=coordinator,
                entry=entry,
                client=client,
                iface_id=iface_id,
                profile=profile,
            )
        )
        
    if entities:
        async_add_entities(entities)


class BaseKeeneticSwitch(CoordinatorEntity, SwitchEntity):
    """Base switch class sharing device_info + refresh logic."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        client: KeeneticClient,
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._client = client

    @property
    def device_info(self) -> dict[str, Any]:
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name": self._entry.title,
            "manufacturer": "Keenetic",
        }


class KeeneticWifiSwitch(BaseKeeneticSwitch):
    """Wi-Fi SSID / interface aç/kapat switch'i."""

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        client: KeeneticClient,
        interface_id: str,
        display_name: str,
    ) -> None:
        super().__init__(coordinator, entry, client)
        self._interface_id = interface_id
        self._display_name = display_name
        # Örn: "Wi-Fi WifiMaster0" / "Wi-Fi WifiMaster1"
        self._attr_name = f"Wi-Fi {self._display_name}"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_wifi_{self._interface_id}"

    @property
    def is_on(self) -> bool:
        for net in self.coordinator.data.get("wifi", []):
            nid = net.get("id") or net.get("name")
            if nid == self._interface_id:
                enabled = net.get("enabled")
                if enabled is not None:
                    return bool(enabled)
                # Bazı durumlarda sadece state: up/down olabilir
                state = str(net.get("state", "")).lower()
                if state:
                    return state == "up"
        return False

    async def async_turn_on(self, **_: Any) -> None:
        await self._client.async_set_wifi_enabled(self._interface_id, True)
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **_: Any) -> None:
        await self._client.async_set_wifi_enabled(self._interface_id, False)
        await self.coordinator.async_request_refresh()


class KeeneticVpnSwitch(BaseKeeneticSwitch):
    """Genel VPN tüneli aç/kapat switch'i (WireGuard, OpenVPN, IPsec, ...)."""

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        client: KeeneticClient,
        iface_id: str,
        profile: dict[str, Any],
    ) -> None:
        super().__init__(coordinator, entry, client)
        self._iface_id = iface_id  # Örn: "Wireguard5", "OpenVpn0"
        self._profile_type = str(profile.get("type") or "").lower()
        self._label = profile.get("label") or iface_id

        # İsimlendirme: "Wireguard - Stockholm", "OpenVPN - Office", "VPN - X"
        if self._profile_type == "wireguard":
            prefix = "Wireguard"
        elif self._profile_type:
            # Type'ı ilk harf büyük yapalım
            prefix = self._profile_type.capitalize()
        else:
            prefix = "VPN"

        self._attr_name = f"{prefix} - {self._label}"

    @property
    def unique_id(self) -> str:
        return f"{self._entry.entry_id}_vpn_{self._iface_id}"

    # ---- Durum ----

    def _current_profile(self) -> dict[str, Any]:
        vpn = self.coordinator.data.get("vpn_tunnels", {}) or {}
        profiles = vpn.get("profiles", {}) or {}
        return profiles.get(self._iface_id, {}) or {}

    @property
    def is_on(self) -> bool:
        prof = self._current_profile()
        if "enabled" in prof:
            return bool(prof["enabled"])
        state = str(prof.get("state") or "").lower()
        if state:
            return state == "up"
        return False

    # ---- Komutlar ----

    async def async_turn_on(self, **_: Any) -> None:
        # Not: async_set_wireguard_enabled aslında generic "interface up/down"
        await self._client.async_set_wireguard_enabled(self._iface_id, True)
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **_: Any) -> None:
        await self._client.async_set_wireguard_enabled(self._iface_id, False)
        await self.coordinator.async_request_refresh()

