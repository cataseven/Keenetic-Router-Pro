"""VPN client tunnel and SSTP server sensors (issue #74).

WireGuard tunnels already have uptime / RX / TX sensors (wireguard.py);
these cover the other VPN client types (SSTP, OpenVPN, L2TP, PPTP, ...)
and the router's own SSTP VPN server.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory, UnitOfInformation, UnitOfTime

from ..coordinator import KeeneticCoordinator
from ..entity import ControllerEntity
from ..utils import safe_float, vpn_label, vpn_prefix
from .monotonic import MonotonicUptimeMixin


class _BaseVpnSensor(ControllerEntity, SensorEntity):
    """A VPN client tunnel's diagnostic sensor; off by default."""

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False
    _KIND = ""

    def __init__(
        self, coordinator: KeeneticCoordinator, entry: ConfigEntry, iface_id: str
    ) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)
        self._iface_id = iface_id
        profiles = self._profiles
        profile = profiles.get(iface_id) or {}
        self._attr_name = (
            f"{vpn_prefix(profile.get('type'))} - "
            f"{vpn_label(profiles, iface_id)} {self._KIND}"
        )

    @property
    def _profiles(self) -> dict[str, Any]:
        vpn = self.coordinator.data.get("vpn_tunnels") or {}
        return vpn.get("profiles") or {}

    @property
    def _profile(self) -> dict[str, Any] | None:
        profile = self._profiles.get(self._iface_id)
        return profile if isinstance(profile, dict) else None

    @property
    def available(self) -> bool:
        return super().available and self._profile is not None


class KeeneticVpnUptimeSensor(MonotonicUptimeMixin, _BaseVpnSensor):
    """Seconds the tunnel session has been up; 0 while it is down.

    A reset shows a reconnect that happened between two polls, which the
    Connected sensor cannot see.
    """

    _KIND = "Uptime"
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = UnitOfTime.SECONDS
    _attr_suggested_display_precision = 0

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_vpn_{self._iface_id}_uptime"

    @property
    def native_value(self) -> int | None:
        profile = self._profile
        if profile is None:
            return None
        uptime = profile.get("uptime")
        if uptime is not None:
            # The router's session counter, also while a ping-check failure
            # has the Connected sensor off: the session itself is still up.
            return self._clamp_monotonic(uptime)
        if profile.get("connected") is False:
            return self._clamp_monotonic(0)
        return None


class _VpnTrafficSensor(_BaseVpnSensor):
    """Bytes through the tunnel, from show/interface/stat (already polled)."""

    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = UnitOfInformation.MEGABYTES
    _attr_suggested_display_precision = 2
    _FIELD = ""

    @property
    def native_value(self) -> float | None:
        stats = (self.coordinator.data.get("interface_stats") or {}).get(self._iface_id)
        if not isinstance(stats, dict):
            return None
        value = safe_float(stats.get(self._FIELD))
        return None if value is None else round(value / (1024 * 1024), 2)


class KeeneticVpnRxSensor(_VpnTrafficSensor):
    _KIND = "RX"
    _FIELD = "rxbytes"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_vpn_{self._iface_id}_rx"


class KeeneticVpnTxSensor(_VpnTrafficSensor):
    _KIND = "TX"
    _FIELD = "txbytes"

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_vpn_{self._iface_id}_tx"


class KeeneticSstpServerSessionsSensor(ControllerEntity, SensorEntity):
    """Clients connected to the router's own SSTP VPN server (issue #74).

    State: the number of sessions. Attributes: whether the server is on,
    and who is connected, so an automation can watch one client with a
    template such as ``'z2m' in state_attr(..., 'usernames')``.
    """

    _attr_has_entity_name = True
    _attr_name = "SSTP Server Sessions"
    _attr_icon = "mdi:vpn"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: KeeneticCoordinator, entry: ConfigEntry) -> None:
        ControllerEntity.__init__(self, coordinator, entry.entry_id, entry.title)

    @property
    def _server(self) -> dict[str, Any] | None:
        server = self.coordinator.data.get("sstp_server")
        return server if isinstance(server, dict) else None

    @property
    def unique_id(self) -> str:
        return f"{self._entry_id}_sstp_server_sessions"

    @property
    def available(self) -> bool:
        return super().available and self._server is not None

    @property
    def native_value(self) -> int | None:
        server = self._server
        return None if server is None else len(server.get("sessions") or [])

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        server = self._server
        if server is None:
            return None
        sessions = server.get("sessions") or []
        return {
            "server_enabled": server.get("enabled"),
            "usernames": sorted({s.get("username") for s in sessions if s.get("username")}),
            "clients": [
                {"username": s.get("username"), "address": s.get("client_address")}
                for s in sessions
            ],
        }
