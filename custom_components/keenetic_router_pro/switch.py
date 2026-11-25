"""Switches for Keenetic Router Pro (Wi-Fi, VPN, IPsec, port forwarding)."""
from __future__ import annotations
from typing import Any
from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from aiohttp import ClientError
from .api import KeeneticApiError, KeeneticClient, describe_error
from .const import DOMAIN, DATA_CLIENT, DATA_COORDINATOR
from .coordinator import KeeneticCoordinator
from .entity import ControllerEntity, CryptoMapEntity
from .utils import vpn_prefix


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

    # Port forwarding rules: one switch per rule, picked up from the web
    # UI without a restart. Rules that are deleted later turn the
    # switch unavailable.
    known_forward_indexes: set[str] = set()

    @callback
    def _async_add_new_port_forwards() -> None:
        new_entities: list[SwitchEntity] = []
        for index, rule in (coordinator.data.get("port_forwards") or {}).items():
            if index in known_forward_indexes:
                continue
            known_forward_indexes.add(index)
            new_entities.append(
                KeeneticPortForwardSwitch(coordinator, entry, client, index, rule)
            )
        if new_entities:
            async_add_entities(new_entities)

    _async_add_new_port_forwards()
    entry.async_on_unload(
        coordinator.async_add_listener(_async_add_new_port_forwards)
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


class KeeneticPortForwardSwitch(BaseKeeneticSwitch):
    """Turn an existing port forwarding rule on or off.

    Safety, because an "on" here opens a port to the internet:
    * disabled by default — the user enables only the rules they want;
    * ``EntityCategory.CONFIG`` — Home Assistant does not expose
      configuration entities to Assist, LLM agents or HomeKit by
      default, so a voice command cannot open a port by accident;
    * the api layer re-reads the rule, verifies the change and only
      then saves the router configuration.
    """

    _attr_entity_registry_enabled_default = False
    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:lan-connect"

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        client: KeeneticClient,
        index: str,
        rule: dict[str, Any],
    ) -> None:
        super().__init__(coordinator, entry, client)
        self._index = index
        self._attr_unique_id = f"{entry.entry_id}_port_forward_{index}"
        # "Port forward NAS TCP 8443 (ISP)", "Port forward UDP 51820-51821
        # (ISP)". Protocol, port and interface are always part of the name:
        # the same port is often forwarded once per WAN, and several rules
        # often share one comment. The user picks which switch to enable
        # from the disabled list, where no attributes are shown.
        parts = (
            str(rule.get("name") or ""),
            str(rule.get("protocol") or "").upper(),
            self._ports(rule),
        )
        label = " ".join(part for part in parts if part)
        self._attr_name = f"Port forward {label} ({rule.get('interface')})"

    @staticmethod
    def _ports(rule: dict[str, Any]) -> str:
        ports = str(rule.get("port"))
        if rule.get("end_port") is not None:
            ports += f"-{rule['end_port']}"
        return ports

    @property
    def _rule(self) -> dict[str, Any] | None:
        rules = self.coordinator.data.get("port_forwards") or {}
        rule = rules.get(self._index)
        return rule if isinstance(rule, dict) else None

    @property
    def available(self) -> bool:
        return super().available and self._rule is not None

    @property
    def is_on(self) -> bool | None:
        rule = self._rule
        return rule["enabled"] if rule is not None else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        rule = self._rule
        if rule is None:
            return None
        return {
            "interface": rule.get("interface"),
            "protocol": rule.get("protocol"),
            "port": self._ports(rule),
            "to_port": rule.get("to_port"),
            "comment": rule.get("name") or None,
        }

    async def _async_set_enabled(self, enabled: bool) -> None:
        try:
            rules = await self._client.async_set_port_forward_enabled(
                self._index, enabled
            )
        except (KeeneticApiError, TimeoutError, ClientError, ValueError) as err:
            # Show what the router really has now.
            await self.coordinator.async_request_refresh()
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="port_forward_set_failed",
                translation_placeholders={"error": describe_error(err)},
            ) from err
        # Publish the state the router just confirmed. A requested refresh
        # would be held back while a poll is running, and that poll read
        # the rules before the change.
        self.coordinator.async_set_updated_data(
            {**self.coordinator.data, "port_forwards": rules}
        )

    async def async_turn_on(self, **_: Any) -> None:
        await self._async_set_enabled(True)

    async def async_turn_off(self, **_: Any) -> None:
        await self._async_set_enabled(False)


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

        self._attr_name = f"{vpn_prefix(self._profile_type)} - {self._label}"

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
