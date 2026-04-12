"""DataUpdateCoordinator for Keenetic Router Pro."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import KeeneticClient
from .const import DOMAIN, FAST_SCAN_INTERVAL, PING_SCAN_INTERVAL, DEFAULT_PING_INTERVAL

import logging

_LOGGER = logging.getLogger(f"custom_components.{DOMAIN}.coordinator")

# ICMP ping için icmplib kullanıyoruz (Home Assistant Ping entegrasyonu gibi)
try:
    from icmplib import async_ping, SocketPermissionError
    ICMPLIB_AVAILABLE = True
except ImportError:
    ICMPLIB_AVAILABLE = False
    _LOGGER.warning("icmplib not available, ping-based tracking will not work")


class KeeneticCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Tek yerden tüm router verisini toplayan coordinator."""

    def __init__(self, hass: HomeAssistant, client: KeeneticClient) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name="keenetic_router_pro",
            update_interval=timedelta(seconds=FAST_SCAN_INTERVAL),
        )
        self.client = client

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch all router data with bounded, staged parallelism.
 
        The Keenetic RCI endpoint is a single HTTP surface served by a
        modest router CPU, so we cap concurrency at 4 in-flight calls
        with a semaphore. Calls are split into dependency stages:
 
          * Stage 1 has no dependencies and runs first.
          * Stage 2 needs ``interfaces`` from stage 1.
          * Stage 3 needs results from stages 1 and 2 (WiFi passwords
            per SSID, USB devices per connected mesh node).
 
        Within each stage we use ``asyncio.gather`` with
        ``return_exceptions=True`` so a single failing endpoint can no
        longer kill the whole update tick — failed fetches are
        normalised to safe defaults of the same shape the downstream
        code expects, and the next tick simply retries them.
        """
        sem = asyncio.Semaphore(4)
 
        async def _bounded(coro):
            async with sem:
                return await coro
 
        def _ok(value, default):
            """Replace failed fetches with a safe default of the right shape."""
            if isinstance(value, BaseException):
                _LOGGER.debug("Coordinator fetch failed, using default: %s", value)
                return default
            return value
 
        # ---------- Stage 1: independent fetches ----------
        (
            system,
            version,
            version_available,
            interfaces,
            clients,
            mesh_nodes,
            client_stats,
            host_policies,
            ndns_info,
            usb_storage,
            interface_stats,
            ping_check_status,
        ) = await asyncio.gather(
            _bounded(self.client.async_get_system_info()),
            _bounded(self.client.async_get_current_version_info()),
            _bounded(self.client.async_get_available_version_info()),
            _bounded(self.client.async_get_interfaces()),
            _bounded(self.client.async_get_clients()),
            _bounded(self.client.async_get_mesh_nodes()),
            _bounded(self.client.async_get_client_stats()),
            _bounded(self.client.async_get_host_policies()),
            _bounded(self.client.async_get_ndns_info()),
            _bounded(self.client.async_get_usb_storage()),
            _bounded(self.client.async_get_all_interface_stats()),
            _bounded(self.client.async_get_ping_check_status()),
            return_exceptions=True,
        )
 
        system = _ok(system, {})
        version = _ok(version, {})
        version_available = _ok(version_available, {})
        interfaces = _ok(interfaces, [])
        clients = _ok(clients, [])
        mesh_nodes = _ok(mesh_nodes, [])
        client_stats = _ok(client_stats, {})
        host_policies = _ok(host_policies, {})
        ndns_info = _ok(ndns_info, {})
        usb_storage = _ok(usb_storage, [])
        interface_stats = _ok(interface_stats, {})
        ping_check_status = _ok(ping_check_status, {})
 
        merged_system = {**system, **version}
        merged_system["release-available"] = (
            version_available.get("title") or version_available.get("release")
        )
        merged_system["fw-update-sandbox"] = version_available.get("sandbox")
        merged_system["fw-update-available"] = version_available.get(
            "update-available", False
        )
 
        # ---------- Stage 2: depends on stage-1 `interfaces` ----------
        # All of these accept a pre-fetched ``interfaces=`` argument so
        # we don't re-query the router for the same data once per call.
        (
            wifi,
            wireguard,
            vpn_tunnels,
            wan_status,
            wan_interfaces,
            traffic_stats,
            port_info,
        ) = await asyncio.gather(
            _bounded(self.client.async_get_wifi_networks(interfaces=interfaces)),
            _bounded(self.client.async_get_wireguard_status(interfaces=interfaces)),
            _bounded(self.client.async_get_vpn_tunnels(interfaces=interfaces)),
            _bounded(self.client.async_get_wan_status(interfaces=interfaces)),
            _bounded(self.client.async_get_wan_interfaces(interfaces=interfaces)),
            _bounded(self.client.async_get_traffic_stats(interfaces=interfaces)),
            _bounded(self.client.async_get_port_info(interfaces=interfaces)),
            return_exceptions=True,
        )
 
        wifi = _ok(wifi, [])
        wireguard = _ok(wireguard, [])
        vpn_tunnels = _ok(vpn_tunnels, [])
        wan_status = _ok(wan_status, {})
        wan_interfaces = _ok(wan_interfaces, [])
        traffic_stats = _ok(traffic_stats, {})
        port_info = _ok(port_info, {})
 
        # ---------- Stage 3a: WiFi passwords (parallel, cached) ----------
        # We only fetch a password once per SSID/interface and cache it
        # in coordinator data so subsequent ticks skip these calls
        # entirely. The first tick after a fresh start does N parallel
        # fetches; every tick after that does zero.
        wifi_passwords: dict[str, str] = {}
        if self.data:
            wifi_passwords = dict(self.data.get("wifi_passwords", {}))
 
        missing_pw_targets = [
            (net.get("id"), net.get("ssid"))
            for net in wifi
            if net.get("id")
            and net.get("ssid")
            and net.get("id") not in wifi_passwords
        ]
        if missing_pw_targets:
            pw_results = await asyncio.gather(
                *(
                    _bounded(self.client.async_get_wifi_password(iface_id))
                    for iface_id, _ssid in missing_pw_targets
                ),
                return_exceptions=True,
            )
            for (iface_id, _ssid), pw in zip(missing_pw_targets, pw_results):
                if isinstance(pw, BaseException):
                    continue
                if pw:
                    wifi_passwords[iface_id] = pw
 
        # ---------- Stage 3b: Mesh USB (parallel per node) ----------
        # Each connected mesh node is queried directly at its own IP
        # for its USB storage. These calls are independent of each
        # other and of the main router, so they fan out cleanly.
        connected_nodes = [
            n for n in mesh_nodes if n.get("ip") and n.get("connected", False)
        ]
 
        async def _fetch_node_usb(node: dict[str, Any]) -> list[dict[str, Any]]:
            node_ip = node.get("ip")
            cid = node.get("cid")
            node_name = node.get("name") or node.get("mac") or cid or node_ip
            try:
                node_usb = await self.client.async_get_mesh_node_usb(
                    node_ip=node_ip,
                    node_name=node_name,
                    node_cid=cid or "",
                )
            except Exception:
                return []
            if not node_usb:
                return []
            for dev in node_usb:
                dev["mesh_node_name"] = node_name
            return node_usb
 
        mesh_usb: list[dict[str, Any]] = []
        if connected_nodes:
            node_usb_results = await asyncio.gather(
                *(_bounded(_fetch_node_usb(n)) for n in connected_nodes),
                return_exceptions=True,
            )
            for res in node_usb_results:
                if isinstance(res, BaseException):
                    continue
                mesh_usb.extend(res)
 
        # ---------- WAN enrichment (CPU-only, runs on already-fetched
        # data — logic unchanged from the sequential implementation) ----------
        #
        # We reuse the already-fetched ``interface_stats`` (show/interface/stat
        # for every interface) instead of firing extra RCI calls. Throughput
        # is computed as a delta against the previous coordinator tick.
        prev_wan_by_id: dict[str, dict[str, Any]] = {}
        if self.data:
            for prev in self.data.get("wan_interfaces", []) or []:
                pid = prev.get("id")
                if pid:
                    prev_wan_by_id[pid] = prev
        now_ts = asyncio.get_event_loop().time()
 
        def _to_int(v: Any) -> int:
            try:
                return int(v)
            except (TypeError, ValueError):
                return 0
 
        for wan in wan_interfaces:
            wan_id = wan.get("id")
            stats = (interface_stats or {}).get(wan_id) or {}
            rx_bytes = _to_int(
                stats.get("rxbytes")
                or stats.get("rx-bytes")
                or stats.get("rx_bytes")
            )
            tx_bytes = _to_int(
                stats.get("txbytes")
                or stats.get("tx-bytes")
                or stats.get("tx_bytes")
            )
            wan["rx_bytes"] = rx_bytes
            wan["tx_bytes"] = tx_bytes
            wan["rx_packets"] = _to_int(
                stats.get("rxpackets") or stats.get("rx-packets")
            )
            wan["tx_packets"] = _to_int(
                stats.get("txpackets") or stats.get("tx-packets")
            )
            wan["_sample_ts"] = now_ts
 
            # --- Authoritative ping-check override ---
            # When the router itself reports a ping-check result for
            # this WAN, trust it over the heuristic. Three cases:
            #   passing=True  -> internet_access=True (ping check ok)
            #   passing=False -> internet_access=False (real outage,
            #                    the case the feature request is about)
            #   passing=None  -> no real profile attached / mixed state
            #                    -> keep the heuristic value from api.py
            pc = ping_check_status.get(wan_id)
            if pc is not None:
                wan["ping_check"] = pc
                passing = pc.get("passing")
                if passing is True or passing is False:
                    wan["internet_access"] = passing
                    wan["internet_access_source"] = "ping_check"
                else:
                    wan["internet_access_source"] = "heuristic"
            else:
                wan["ping_check"] = None
                wan["internet_access_source"] = "heuristic"
 
            prev = prev_wan_by_id.get(wan_id)
            if prev and prev.get("_sample_ts"):
                dt = now_ts - float(prev.get("_sample_ts") or 0)
                if dt > 0:
                    d_rx = rx_bytes - _to_int(prev.get("rx_bytes"))
                    d_tx = tx_bytes - _to_int(prev.get("tx_bytes"))
                    # Counter wraps / resets (interface bounced): treat as 0.
                    wan["rx_throughput"] = max(0.0, d_rx / dt) if d_rx >= 0 else 0.0
                    wan["tx_throughput"] = max(0.0, d_tx / dt) if d_tx >= 0 else 0.0
                else:
                    wan["rx_throughput"] = 0.0
                    wan["tx_throughput"] = 0.0
            else:
                wan["rx_throughput"] = 0.0
                wan["tx_throughput"] = 0.0
 
        # Role labels: the interface with ``defaultgw: true`` is the
        # Default connection. The rest are Backup connection 1..N
        # ordered by priority descending (higher Keenetic priority =
        # next in line for failover).
        default_idx: int | None = None
        for i, wan in enumerate(wan_interfaces):
            if wan.get("defaultgw"):
                default_idx = i
                break
 
        def _prio_key(w: dict[str, Any]) -> int:
            p = w.get("priority")
            return -int(p) if isinstance(p, (int, float)) else 0
 
        if default_idx is not None:
            default = wan_interfaces[default_idx]
            backups = [
                w for i, w in enumerate(wan_interfaces) if i != default_idx
            ]
            backups.sort(key=_prio_key)
            ordered = [default] + backups
        else:
            ordered = sorted(wan_interfaces, key=_prio_key)
 
        for position, wan in enumerate(ordered):
            if position == 0 and (wan.get("defaultgw") or default_idx is None):
                wan["role_label"] = "Default connection"
                wan["role_index"] = 0
            else:
                idx = position if default_idx is None else position
                wan["role_label"] = f"Backup connection {idx}"
                wan["role_index"] = idx
        wan_interfaces = ordered
 
        # ---------- New-client detection (unchanged) ----------
        previous_clients = self.data.get("clients", []) if self.data else []
        previous_macs = {
            str(c.get("mac") or "").lower()
            for c in previous_clients
            if c.get("mac")
        }
        current_macs = {
            str(c.get("mac") or "").lower() for c in clients if c.get("mac")
        }
        new_macs = current_macs - previous_macs
 
        return {
            "system": merged_system,
            "traffic_stats": traffic_stats,
            "interfaces": interfaces,
            "wifi": wifi,
            "wifi_passwords": wifi_passwords,
            "wireguard": wireguard,
            "vpn_tunnels": vpn_tunnels,
            "clients": clients,
            "wan_status": wan_status,
            "wan_interfaces": wan_interfaces,
            "mesh_nodes": mesh_nodes,
            "interface_stats": interface_stats,
            "client_stats": client_stats,
            "ndns": ndns_info,
            "host_policies": host_policies,
            "usb_storage": usb_storage,
            "port_info": port_info,
            "mesh_usb": mesh_usb,
            "new_clients": new_macs,
        }


class KeeneticPingCoordinator(DataUpdateCoordinator[dict[str, bool]]):
    """Coordinator for ICMP ping-based presence detection of tracked clients.
    
    Uses real ICMP ping (like Home Assistant's Ping integration) instead of
    router API to detect if a device is actually connected to the network.
    """

    # Ping configuration
    PING_COUNT = 1          # Gönderilecek ping sayısı (hızlı döngü için 1 yeterli)
    PING_TIMEOUT = 1        # Her ping için timeout (saniye)
    PING_PRIVILEGED = False # Unprivileged mode (root gerektirmez)

    @staticmethod
    def _is_valid_ip(ip: Any) -> bool:
        """Is this a usable IPv4 address for presence pinging?

        A client that has left the network often shows up in the router
        API with an IP of "0.0.0.0", an empty string, or None. Pinging
        any of these is meaningless at best and produces *false positive*
        "alive" results at worst (0.0.0.0 can resolve to the local host
        on some Linux kernels, which icmplib then reports as reachable —
        flipping the device tracker back to "home" even though the phone
        is actually miles away). Centralising the check in one place
        prevents stale addresses from leaking into the ping loop.
        """
        if ip is None:
            return False
        s = str(ip).strip()
        if not s:
            return False
        if s in ("0.0.0.0", "::", "::0", "0:0:0:0:0:0:0:0"):
            return False
        # Reject obviously malformed values without pulling in ipaddress
        # on the hot path — we only need to catch the common router
        # placeholders.
        if s.startswith("0."):
            return False
        return True

    def __init__(
        self,
        hass: HomeAssistant,
        client: KeeneticClient,
        tracked_clients: list[dict[str, str]],
        interval: int | None = None,
    ) -> None:
        """Initialize the ping coordinator.
        
        Args:
            hass: Home Assistant instance
            client: Keenetic API client (used for IP updates from router)
            tracked_clients: List of dicts with 'mac', 'ip', 'name' keys
            interval: Ping refresh interval in seconds. Defaults to
                DEFAULT_PING_INTERVAL when not provided. Can be reconfigured
                from the integration's options flow.
        """
        if interval is None or interval <= 0:
            interval = DEFAULT_PING_INTERVAL
        super().__init__(
            hass,
            _LOGGER,
            name="keenetic_router_pro_ping",
            update_interval=timedelta(seconds=interval),
        )
        self.client = client
        self._tracked_clients = tracked_clients
        self._privileged: bool | None = None  # Will be determined on first ping
        
        # MAC -> IP mapping (güncellenebilir)
        self._mac_to_ip: dict[str, str] = {}
        for c in tracked_clients:
            # Defensive: handle both dict and plain string (MAC) formats
            if isinstance(c, dict):
                mac = str(c.get("mac") or "").lower()
                ip = str(c.get("ip") or "")
            else:
                mac = str(c).lower()
                ip = ""
            if mac and self._is_valid_ip(ip):
                self._mac_to_ip[mac] = ip

    def update_tracked_clients(self, tracked_clients: list[dict[str, str]]) -> None:
        """Update the list of tracked clients."""
        self._tracked_clients = tracked_clients
        self._mac_to_ip = {}
        for c in tracked_clients:
            if isinstance(c, dict):
                mac = str(c.get("mac") or "").lower()
                ip = str(c.get("ip") or "")
            else:
                mac = str(c).lower()
                ip = ""
            if mac and self._is_valid_ip(ip):
                self._mac_to_ip[mac] = ip

    def update_client_ip(self, mac: str, ip: str) -> None:
        """Update IP address for a specific client (dynamic IP support).

        Invalid/placeholder addresses like "0.0.0.0" or empty strings
        are rejected *and* remove any previously-cached IP for this
        MAC. Rationale: when a client leaves the network the router
        first reports the stale last-known IP for ~30s and then resets
        it to 0.0.0.0. Without this cleanup, the ping loop would either
        keep pinging the stale address (false negative) or ping
        0.0.0.0 which some kernels happily answer (false positive —
        the device tracker flips back to "home" from kilometres away).
        Dropping the MAC from the ping map causes `_async_update_data`
        to report False for this client until a new valid lease shows
        up, which matches the user's expectation.
        """
        mac_lower = mac.lower()
        if self._is_valid_ip(ip):
            self._mac_to_ip[mac_lower] = str(ip).strip()
        else:
            # Remove stale entry so the ping loop stops reporting on it.
            self._mac_to_ip.pop(mac_lower, None)

    def get_tracked_macs(self) -> set[str]:
        """Return set of tracked MAC addresses."""
        result = set()
        for c in self._tracked_clients:
            if isinstance(c, dict):
                mac = str(c.get("mac") or "").lower()
            else:
                mac = str(c).lower()
            if mac:
                result.add(mac)
        return result

    def get_client_info(self, mac: str) -> dict[str, str] | None:
        """Get client info by MAC address."""
        mac_lower = mac.lower()
        for c in self._tracked_clients:
            if isinstance(c, dict):
                if str(c.get("mac") or "").lower() == mac_lower:
                    return c
            else:
                if str(c).lower() == mac_lower:
                    return {"mac": str(c).lower(), "ip": "", "name": ""}
        return None

    async def _async_ping_host(self, ip: str) -> bool:
        """Ping a single host using ICMP.
        
        Returns True if host is alive, False otherwise.
        """
        # Belt-and-braces: even if a caller somehow slips a placeholder
        # address past the map-level validation, refuse to actually
        # send ICMP to it. icmplib will happily "ping" 0.0.0.0 on some
        # kernels and report the host as alive, which is exactly the
        # false-positive that made device_tracker flip back to "home"
        # after the router cleared the client's lease.
        if not self._is_valid_ip(ip):
            _LOGGER.debug("Refusing to ping invalid address %r", ip)
            return False

        if not ICMPLIB_AVAILABLE:
            _LOGGER.warning("icmplib not available, cannot ping %s", ip)
            return False

        try:
            # İlk denemede privileged mode'u belirle
            if self._privileged is None:
                self._privileged = self.PING_PRIVILEGED
            
            # Gerçek ICMP ping gönder
            result = await async_ping(
                ip,
                count=self.PING_COUNT,
                timeout=self.PING_TIMEOUT,
                privileged=self._privileged,
            )
            
            is_alive = result.is_alive
            _LOGGER.debug(
                "Ping %s: alive=%s, packets_sent=%d, packets_received=%d, avg_rtt=%.2fms",
                ip,
                is_alive,
                result.packets_sent,
                result.packets_received,
                result.avg_rtt if result.avg_rtt else 0,
            )
            return is_alive
            
        except SocketPermissionError:
            # Unprivileged mode çalışmadıysa privileged dene
            if not self._privileged:
                _LOGGER.info(
                    "Unprivileged ICMP ping failed, trying privileged mode for %s", ip
                )
                self._privileged = True
                return await self._async_ping_host(ip)
            _LOGGER.error(
                "ICMP ping requires root privileges. "
                "Run Home Assistant as root or enable unprivileged ping: "
                "sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'"
            )
            return False
            
        except BaseException as err:
            # asyncio.CancelledError Python 3.8+'da BaseException'dan türer,
            # bu yüzden normal Exception bloğu onu yakalamaz.
            if isinstance(err, asyncio.CancelledError):
                _LOGGER.debug("Ping to %s was cancelled", ip)
                return False
            _LOGGER.debug("Ping to %s failed: %s", ip, err)
            return False

    async def _async_update_data(self) -> dict[str, bool]:
        """Ping all tracked clients using ICMP and return their status.
        
        Returns:
            Dict mapping MAC addresses to their connected status (True/False)
        """
        # Every tracked MAC must appear in the result, even if we have
        # no valid IP for it right now — otherwise the device_tracker
        # entity keeps showing its last (stale) state forever. MACs
        # without a usable address are explicitly reported as False so
        # the tracker correctly flips to "not_home".
        tracked_macs = self.get_tracked_macs()
        mac_status: dict[str, bool] = {mac: False for mac in tracked_macs}

        if not self._mac_to_ip:
            _LOGGER.debug("No IP addresses to ping")
            return mac_status

        if not ICMPLIB_AVAILABLE:
            _LOGGER.error("icmplib not installed, ping tracking disabled")
            return mac_status

        # Tüm ping'leri paralel olarak çalıştır
        tasks = []
        macs = []

        for mac, ip in self._mac_to_ip.items():
            if not self._is_valid_ip(ip):
                # Paranoid: validation happens on write, but double-check
                # on read in case something mutated the map out-of-band.
                continue
            tasks.append(self._async_ping_host(ip))
            macs.append(mac)

        # Tüm ping'leri bekle
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Sonuçları MAC adresine göre eşle
        for mac, result in zip(macs, results):
            if isinstance(result, BaseException):
                _LOGGER.debug("Ping exception for %s: %s", mac, result)
                mac_status[mac] = False
            else:
                mac_status[mac] = bool(result)

        _LOGGER.debug("ICMP Ping results: %s", mac_status)

        return mac_status
