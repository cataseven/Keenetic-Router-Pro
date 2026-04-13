"""Binary sensors for Keenetic Router Pro (Mesh AP status)."""
from __future__ import annotations
from typing import Any
from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorDeviceClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .const import DOMAIN, DATA_COORDINATOR
from .coordinator import KeeneticCoordinator
from .entity import MeshEntity, ControllerEntity, WanEntity, CryptoMapEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic Router Pro binary sensors from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: KeeneticCoordinator = data[DATA_COORDINATOR]
    entities: list[BinarySensorEntity] = []

    entities.append(KeeneticControllerUpdateSensor(coordinator, entry))

    # Mesh node'lar için binary sensor
    mesh_nodes = coordinator.data.get("mesh_nodes", [])
    for node in mesh_nodes:
        node_cid = node.get("cid") or node.get("id")
        if node_cid:
            entities.append(KeeneticMeshNodeSensor(coordinator, entry, node_cid))
            entities.append(KeeneticMeshUpdateSensor(coordinator, entry, node_cid))

    # Per-WAN binary sensors: one "Connected" (internet reachability) and
    # one "Enabled" (UI toggle) per uplink.
    known_wan_ids: set[str] = set()
    wan_interfaces = coordinator.data.get("wan_interfaces", []) or []
    for wan in wan_interfaces:
        wan_id = wan.get("id")
        if not wan_id or wan_id in known_wan_ids:
            continue
        known_wan_ids.add(wan_id)
        entities.append(KeeneticWanConnectedSensor(coordinator, entry, wan_id))
        entities.append(KeeneticWanEnabledSensor(coordinator, entry, wan_id))

    # Per-crypto-map binary sensor: "Connected" (phase2 established).
    # Tunnels can be added/removed at runtime via the web UI, so we
    # also register a listener below to catch new ones.
    known_cmap_names: set[str] = set()
    for cmap_name in (coordinator.data.get("crypto_maps") or {}).keys():
        if cmap_name in known_cmap_names:
            continue
        known_cmap_names.add(cmap_name)
        entities.append(
            KeeneticCryptoMapConnectedSensor(coordinator, entry, cmap_name)
        )

    if entities:
        async_add_entities(entities)

    # New WAN interfaces may appear later (LTE stick plugged in, a new
    # PPPoE dialed, an extra WireGuard tunnel configured as uplink).
    # Site-to-site IPsec tunnels can also be added/removed at runtime
    # via the web UI — both kinds of sub-device fan out through this
    # single listener so we use one listener slot for both.
    @callback
    def _async_add_new_sub_devices() -> None:
        new_entities: list[BinarySensorEntity] = []
        for wan in coordinator.data.get("wan_interfaces", []) or []:
            wan_id = wan.get("id")
            if not wan_id or wan_id in known_wan_ids:
                continue
            known_wan_ids.add(wan_id)
            new_entities.append(
                KeeneticWanConnectedSensor(coordinator, entry, wan_id)
            )
            new_entities.append(
                KeeneticWanEnabledSensor(coordinator, entry, wan_id)
            )
        for cmap_name in (coordinator.data.get("crypto_maps") or {}).keys():
            if cmap_name in known_cmap_names:
                continue
            known_cmap_names.add(cmap_name)
            new_entities.append(
                KeeneticCryptoMapConnectedSensor(
                    coordinator, entry, cmap_name
                )
            )
        if new_entities:
            async_add_entities(new_entities)

    entry.async_on_unload(
        coordinator.async_add_listener(_async_add_new_sub_devices)
    )


class KeeneticWanConnectedSensor(WanEntity, BinarySensorEntity):
    """Per-WAN "Connected" sensor — true when the uplink is actually usable.

    This is the signal behind the red "NO INTERNET ACCESS (PING CHECK)"
    badge in the Keenetic web UI and the condition that drives failover
    to a backup WAN. "Usable" here means: link up, global role, has a
    routable public IP, and the router isn't reporting a session
    failure. See api._derive_internet_access for the full logic.
    """

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        wan_id: str,
    ) -> None:
        WanEntity.__init__(self, coordinator, entry.entry_id, entry.title, wan_id)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_connected"

    @property
    def name(self) -> str:
        return "Connected"

    @property
    def available(self) -> bool:
        if not super().available:
            return False
        wan = self._wan
        if wan is None:
            return False
        # None means "pending / unknown" — surface as unavailable rather
        # than silently flipping to False and triggering bogus outage
        # automations.
        return wan.get("internet_access") is not None

    @property
    def is_on(self) -> bool:
        wan = self._wan
        if wan is None:
            return False
        return bool(wan.get("internet_access"))

    @property
    def icon(self) -> str:
        wan = self._wan
        if wan and wan.get("internet_access"):
            return "mdi:web-check"
        if wan and wan.get("link_state") == "up":
            return "mdi:web-remove"
        return "mdi:web-off"

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        wan = self._wan
        if not wan:
            return None
        attrs: dict[str, Any] = {
            "interface": wan.get("id"),
            "description": wan.get("description"),
            "type": wan.get("type"),
            "link_state": wan.get("link_state"),
            "defaultgw": wan.get("defaultgw"),
            "priority": wan.get("priority"),
            "role_label": wan.get("role_label"),
            "public_ip": wan.get("ip"),
            "underlying": wan.get("underlying"),
            # Where the current reachability value came from — either
            # the router's own ping-check or our link+IP heuristic.
            "source": wan.get("internet_access_source"),
        }

        # Expose authoritative ping-check details when the router is
        # actually running a profile bound to this WAN. These are the
        # attributes the feature request asked for:
        #   - check target(s)
        #   - failure reason / counters
        #   - last check time
        pc = wan.get("ping_check")
        if pc:
            targets = []
            hosts = pc.get("check_hosts") or []
            if hosts:
                targets.extend(hosts)
            addrs = pc.get("check_addresses") or []
            if addrs:
                targets.extend(addrs)
            if targets:
                attrs["check_targets"] = targets
            if pc.get("check_port") is not None:
                attrs["check_port"] = pc.get("check_port")
            if pc.get("check_mode"):
                attrs["check_mode"] = pc.get("check_mode")
            if pc.get("profile"):
                attrs["check_profile"] = pc.get("profile")
            if pc.get("success_count") is not None:
                attrs["success_count"] = pc.get("success_count")
            if pc.get("fail_count") is not None:
                attrs["fail_count"] = pc.get("fail_count")
            if pc.get("max_fails") is not None:
                attrs["max_fails"] = pc.get("max_fails")
            if pc.get("update_interval") is not None:
                attrs["update_interval"] = pc.get("update_interval")
            if pc.get("status"):
                attrs["ping_check_status"] = pc.get("status")
            # Human-readable failure reason: Keenetic doesn't expose a
            # free-form reason string, so we synthesise one from the
            # counters when the check is failing.
            if pc.get("passing") is False:
                fc = pc.get("fail_count") or 0
                mf = pc.get("max_fails")
                if mf:
                    attrs["failure_reason"] = (
                        f"ping check failing ({fc}/{mf} consecutive failures"
                        f" to {', '.join(targets) if targets else 'check targets'})"
                    )
                else:
                    attrs["failure_reason"] = (
                        f"ping check failing to "
                        f"{', '.join(targets) if targets else 'check targets'}"
                    )
            ignored = pc.get("all_profiles")
            if ignored and len(ignored) > 1:
                # Surface all observed profiles for debugging when more
                # than one is touching this interface.
                attrs["all_ping_check_profiles"] = ignored

        layers = wan.get("summary_layers") or {}
        if layers:
            attrs["summary_layers"] = layers
        last_update = getattr(self.coordinator, "last_update_success_time", None)
        if last_update is not None:
            attrs["last_check"] = last_update.isoformat()
        return attrs


class KeeneticWanEnabledSensor(WanEntity, BinarySensorEntity):
    """Per-WAN "Enabled" sensor — matches the UI toggle state.

    True when summary.layer.conf is "running" (interface is configured
    up), False when it's "disabled" (the user has toggled the uplink
    off in the web UI).
    """

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:toggle-switch-variant"

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        wan_id: str,
    ) -> None:
        WanEntity.__init__(self, coordinator, entry.entry_id, entry.title, wan_id)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_wan_{self._wan_id}_enabled"

    @property
    def name(self) -> str:
        return "Enabled"

    @property
    def is_on(self) -> bool:
        wan = self._wan
        if wan is None:
            return False
        return bool(wan.get("enabled"))

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        wan = self._wan
        if not wan:
            return None
        layers = wan.get("summary_layers") or {}
        return {
            "conf": layers.get("conf"),
            "link": layers.get("link"),
            "ipv4": layers.get("ipv4"),
            "ctrl": layers.get("ctrl"),
        }


class KeeneticMeshNodeSensor(MeshEntity, BinarySensorEntity):
    """Binary sensor for mesh/extender node connectivity status."""
    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        node_cid: str,
    ) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "_").replace(":", "_")[:16]
        return f"{safe_cid}_connect_v2"

    @property
    def name(self) -> str:
        return f"Connected"

    @property
    def is_on(self) -> bool:
        node = self._node
        if node:
            return node.get("connected", False)
        return False

    @property
    def icon(self) -> str:
        node = self._node
        if node:
            mode = node.get("mode", "")
            if mode == "extender":
                return "mdi:access-point-network"
            elif mode == "repeater":
                return "mdi:wifi-sync"
        return "mdi:access-point"

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        node = self._node
        if not node:
            return None

        return {
            "cid": self._node_cid,
            "mac": node.get("mac"),
            "ip": node.get("ip"),
            "model": node.get("model"),
            "mode": node.get("mode"),
            "uptime": node.get("uptime"),
            "cpuload": node.get("cpuload"),
            "memory": node.get("memory"),
            "firmware": node.get("firmware"),
            "firmware_available": node.get("firmware_available"),
            "associations": node.get("associations"),
            "rci_errors": node.get("rci_errors"),
        }
    

class KeeneticControllerUpdateSensor(ControllerEntity, BinarySensorEntity):
    """Binary sensor for main controller firmware update availability."""
    
    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.UPDATE
    _attr_icon = "mdi:package-up"

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
    ) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_controller_update"

    @property
    def name(self) -> str:
        return "Update Available"

    @property
    def is_on(self) -> bool:
        """Return True if firmware update is available for controller."""
        system = self.coordinator.data.get("system", {}) or {}
        
        current = system.get("title") or system.get("release")
        available = system.get("fw-available") or system.get("release-available")
        
        if not available or not current:
            return False
        
        if available == current:
            return False
        
        channel = system.get("fw-update-sandbox") or system.get("sandbox", "stable")
        if channel != "stable":
            return False
        
        return True

    @property
    def icon(self) -> str:
        if self.is_on:
            return "mdi:update"
        return "mdi:check-circle"

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        system = self.coordinator.data.get("system", {}) or {}
        
        current = system.get("title") or system.get("release")
        available = system.get("fw-available") or system.get("release-available")
        
        attrs = {
            "current_version": current,
            "update_channel": system.get("fw-update-sandbox") or system.get("sandbox"),
        }
        
        if available:
            attrs["available_version"] = available
        
        return attrs
    
class KeeneticMeshUpdateSensor(MeshEntity, BinarySensorEntity):
    """Binary sensor for mesh/extender firmware update availability."""
    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.UPDATE

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        node_cid: str,
    ) -> None:
        MeshEntity.__init__(self, coordinator, entry.entry_id, entry.title, node_cid)

    @property
    def unique_id(self) -> str:
        safe_cid = self._node_cid.replace("-", "").replace(":", "")[:16]
        return f"{self._entry_id}_mesh_{safe_cid}_update_v2"

    @property
    def name(self) -> str:
        return f"Update Available"

    @property
    def is_on(self) -> bool:
        node = self._node
        if node:
            current = node.get("firmware")
            available = node.get("firmware_available")
            if current and available and current != available:
                return True
        return False

    @property
    def icon(self) -> str:
        if self.is_on:
            return "mdi:update"
        return "mdi:check-circle"

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        node = self._node
        if not node:
            return None
        return {
            "cid": self._node_cid,
            "model": node.get("model"),
            "current_version": node.get("firmware"),
            "available_version": node.get("firmware_available"),
        }

class KeeneticCryptoMapConnectedSensor(CryptoMapEntity, BinarySensorEntity):
    """Per-tunnel "Connected" sensor for site-to-site IPsec.

    True when the tunnel has a fully negotiated phase-2 SA. The
    underlying field is ``status.state`` from ``show/crypto/map``;
    the only value we treat as "up" is ``PHASE2_ESTABLISHED``. Every
    other state (``UNDEFINED``, ``CONNECTING``, ``PHASE1_ONLY``,
    etc.) or a missing state is treated as "not connected".
    """

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry: ConfigEntry,
        cmap_name: str,
    ) -> None:
        CryptoMapEntity.__init__(
            self, coordinator, entry.entry_id, entry.title, cmap_name
        )

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_cmap_{self._cmap_name}_connected"

    @property
    def name(self) -> str:
        return "Connected"

    @property
    def is_on(self) -> bool:
        cmap = self._cmap
        if cmap is None:
            return False
        return bool(cmap.get("connected"))

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        cmap = self._cmap
        if cmap is None:
            return None
        return {
            "state": cmap.get("state"),
            "ike_state": cmap.get("ike_state"),
            "via": cmap.get("via"),
            "remote_peer": cmap.get("remote_peer"),
        }
