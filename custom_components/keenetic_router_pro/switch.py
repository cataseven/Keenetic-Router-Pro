"""Switches for Keenetic Router Pro (Wi-Fi + WireGuard on/off)."""
from __future__ import annotations
from typing import Any
from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .api import KeeneticClient
from .const import DOMAIN, DATA_CLIENT, DATA_COORDINATOR
from .coordinator import KeeneticCoordinator
from .entity import ControllerEntity, CryptoMapEntity


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

    # Per-crypto-map "Enabled" switch. Site-to-site IPsec tunnels
    # have their own enable/disable knob that is distinct from any
    # interface up/down, so they need a dedicated switch class.
    known_cmap_names: set[str] = set()
    for cmap_name in (coordinator.data.get("crypto_maps") or {}).keys():
        if cmap_name in known_cmap_names:
            continue
        known_cmap_names.add(cmap_name)
        entities.append(
            KeeneticCryptoMapEnabledSwitch(
                coordinator=coordinator,
                entry=entry,
                client=client,
                cmap_name=cmap_name,
            )
        )

    if entities:
        async_add_entities(entities)

    # Tunnels added later via the web UI should show up without a HA
    # restart. Wi-Fi and VPN-client switches don't use this listener
    # pattern today (they pick up changes on the next reload), but
    # crypto maps do because they are a brand-new entity family here
    # and we want the better UX from day one.
    @callback
    def _async_add_new_crypto_maps() -> None:
        new_entities: list[SwitchEntity] = []
        for cmap_name in (coordinator.data.get("crypto_maps") or {}).keys():
            if cmap_name in known_cmap_names:
                continue
            known_cmap_names.add(cmap_name)
            new_entities.append(
                KeeneticCryptoMapEnabledSwitch(
                    coordinator=coordinator,
                    entry=entry,
                    client=client,
                    cmap_name=cmap_name,
                )
            )
        if new_entities:
            async_add_entities(new_entities)

    entry.async_on_unload(
        coordinator.async_add_listener(_async_add_new_crypto_maps)
    )


class BaseKeeneticSwitch(ControllerEntity, SwitchEntity):
    """Base switch class sharing device_info + refresh logic."""
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        client: KeeneticClient,
    ) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._client = client


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
        self._attr_name = f"Wi-Fi {self._display_name}"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wifi_{self._interface_id}"

    @property
    def is_on(self) -> bool:
        for net in self.coordinator.data.get("wifi", []):
            nid = net.get("id") or net.get("name")
            if nid == self._interface_id:
                enabled = net.get("enabled")
                if enabled is not None:
                    return bool(enabled)
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
        self._iface_id = iface_id
        self._profile_type = str(profile.get("type") or "").lower()
        self._label = profile.get("label") or iface_id

        if self._profile_type == "wireguard":
            prefix = "Wireguard"
        elif self._profile_type == "sstp":
            prefix = "SSTP"
        elif self._profile_type == "openvpn":
            prefix = "OpenVPN"
        elif self._profile_type == "ipsec":
            prefix = "IPsec"
        elif self._profile_type:
            prefix = self._profile_type.capitalize()
        else:
            prefix = "VPN"

        self._attr_name = f"{prefix} - {self._label}"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_vpn_{self._iface_id}"

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

    async def async_turn_on(self, **_: Any) -> None:
        await self._client.async_set_interface_enabled(self._iface_id, True)
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **_: Any) -> None:
        await self._client.async_set_interface_enabled(self._iface_id, False)
        await self.coordinator.async_request_refresh()

class KeeneticCryptoMapEnabledSwitch(CryptoMapEntity, SwitchEntity):
    """Enable / disable a site-to-site IPsec `crypto map` tunnel.

    Unlike VPN-client interfaces (which go through
    `async_set_interface_enabled`), site-to-site tunnels live under
    their own RCI sub-mode and are toggled with:

        crypto map <name>
          [no] enable

    The api layer also runs ``system configuration save`` after every
    toggle so the change survives a reboot — without that, the user
    would flip the switch, the tunnel would go down, and the next
    router restart would silently bring it back.
    """

    _attr_has_entity_name = True
    _attr_icon = "mdi:vpn"

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        client: KeeneticClient,
        cmap_name: str,
    ) -> None:
        CryptoMapEntity.__init__(
            self, coordinator, entry.entry_id, entry.title, cmap_name
        )
        self._client = client

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_cmap_{self._cmap_name}_enabled"

    @property
    def name(self) -> str:
        return "Enabled"

    @property
    def is_on(self) -> bool:
        cmap = self._cmap
        if cmap is None:
            return False
        return bool(cmap.get("enabled"))

    async def async_turn_on(self, **_: Any) -> None:
        await self._client.async_set_crypto_map_enabled(
            self._cmap_name, True
        )
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **_: Any) -> None:
        await self._client.async_set_crypto_map_enabled(
            self._cmap_name, False
        )
        await self.coordinator.async_request_refresh()
