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
        """Router'dan verileri çek."""
        system = await self.client.async_get_system_info()
        version = await self.client.async_get_current_version_info()
        version_available = await self.client.async_get_available_version_info()
        merged_system = {**system, **version}
        merged_system["release-available"] = version_available.get("title") or version_available.get("release")
        merged_system["fw-update-sandbox"] = version_available.get("sandbox")
        merged_system["fw-update-available"] = version_available.get("update-available", False)

        # Interface verisini bir kez çek, tüm metotlara paylaştır
        interfaces = await self.client.async_get_interfaces()

        wifi = await self.client.async_get_wifi_networks(interfaces=interfaces)
        
        # Fetch WiFi passwords for QR code generation (cache - only fetch if not yet known)
        wifi_passwords: dict[str, str] = {}
        if self.data:
            wifi_passwords = dict(self.data.get("wifi_passwords", {}))
        
        for net in wifi:
            iface_id = net.get("id")
            ssid = net.get("ssid")
            if iface_id and ssid and iface_id not in wifi_passwords:
                try:
                    password = await self.client.async_get_wifi_password(iface_id)
                    if password:
                        wifi_passwords[iface_id] = password
                except Exception:
                    pass
        wireguard = await self.client.async_get_wireguard_status(interfaces=interfaces)
        vpn_tunnels = await self.client.async_get_vpn_tunnels(interfaces=interfaces)
        clients = await self.client.async_get_clients()

        interface_stats = await self.client.async_get_all_interface_stats()
        
        # Yeni veriler
        wan_status = await self.client.async_get_wan_status(interfaces=interfaces)
        try:
            wan_interfaces = await self.client.async_get_wan_interfaces(
                interfaces=interfaces
            )
        except Exception as err:
            _LOGGER.debug("async_get_wan_interfaces failed: %s", err)
            wan_interfaces = []

        # Authoritative ping-check results per WAN (rci/show/ping-check).
        # This is the same data source that drives the red
        # "NO INTERNET ACCESS (PING CHECK)" badge in the web UI and the
        # router's own failover decision.
        try:
            ping_check_status = await self.client.async_get_ping_check_status()
        except Exception as err:
            _LOGGER.debug("async_get_ping_check_status failed: %s", err)
            ping_check_status = {}

        # --- Enrich each WAN with role label, byte counters and throughput
        #
        # We reuse the already-fetched `interface_stats` (show/interface/stat
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
            wan["rx_packets"] = _to_int(stats.get("rxpackets") or stats.get("rx-packets"))
            wan["tx_packets"] = _to_int(stats.get("txpackets") or stats.get("tx-packets"))
            wan["_sample_ts"] = now_ts

            # --- Authoritative ping-check override ---
            # When the router itself reports a ping-check result for
            # this WAN, trust it over the heuristic. Three cases:
            #   passing=True  → internet_access=True (ping check ok)
            #   passing=False → internet_access=False (real outage,
            #                   the case the feature request is about)
            #   passing=None  → no real profile attached / mixed state
            #                   → keep the heuristic value from api.py
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

        # Role labels: the interface with `defaultgw: true` is the
        # Default connection. The rest are Backup connection 1..N ordered
        # by priority descending (higher Keenetic priority = next in line).
        default_idx: int | None = None
        for i, wan in enumerate(wan_interfaces):
            if wan.get("defaultgw"):
                default_idx = i
                break
        # Stable order: default first, then backups by priority desc
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
        mesh_nodes = await self.client.async_get_mesh_nodes()
        traffic_stats = await self.client.async_get_traffic_stats(interfaces=interfaces)
        client_stats = await self.client.async_get_client_stats()
        host_policies = await self.client.async_get_host_policies()
        ndns_info = await self.client.async_get_ndns_info()

        # Ana router USB
        usb_storage = await self.client.async_get_usb_storage()

        # Ana router port bilgileri
        port_info = await self.client.async_get_port_info(interfaces=interfaces)

        # Mesh node USB bilgilerini topla
        # Her member'ın kendi IP'sine doğrudan bağlanıp USB sorgusu yapar
        mesh_usb: list[dict[str, Any]] = []
        for node in mesh_nodes:
            node_ip = node.get("ip")
            cid = node.get("cid")
            if not node_ip or not node.get("connected", False):
                continue
            node_name = node.get("name") or node.get("mac") or cid or node_ip
            try:
                node_usb = await self.client.async_get_mesh_node_usb(
                    node_ip=node_ip,
                    node_name=node_name,
                    node_cid=cid or "",
                )
                if node_usb:
                    for dev in node_usb:
                        dev["mesh_node_name"] = node_name
                    mesh_usb.extend(node_usb)
            except Exception:
                pass

        # Önceki client listesini sakla (yeni cihaz tespiti için)
        previous_clients = self.data.get("clients", []) if self.data else []
        previous_macs = {str(c.get("mac") or "").lower() for c in previous_clients if c.get("mac")}
        
        current_macs = {str(c.get("mac") or "").lower() for c in clients if c.get("mac")}
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
            "new_clients": new_macs,  # Yeni bağlanan MAC'ler
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
            if mac and ip:
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
            if mac and ip:
                self._mac_to_ip[mac] = ip

    def update_client_ip(self, mac: str, ip: str) -> None:
        """Update IP address for a specific client (dynamic IP support)."""
        mac_lower = mac.lower()
        if ip:
            self._mac_to_ip[mac_lower] = ip

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
        if not self._mac_to_ip:
            _LOGGER.debug("No IP addresses to ping")
            return {}

        if not ICMPLIB_AVAILABLE:
            _LOGGER.error("icmplib not installed, ping tracking disabled")
            return {mac: False for mac in self._mac_to_ip}

        # Tüm ping'leri paralel olarak çalıştır
        tasks = []
        macs = []
        
        for mac, ip in self._mac_to_ip.items():
            tasks.append(self._async_ping_host(ip))
            macs.append(mac)
        
        # Tüm ping'leri bekle
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Sonuçları MAC adresine göre eşle
        mac_status: dict[str, bool] = {}
        for mac, result in zip(macs, results):
            if isinstance(result, BaseException):
                _LOGGER.debug("Ping exception for %s: %s", mac, result)
                mac_status[mac] = False
            else:
                mac_status[mac] = bool(result)
        
        _LOGGER.debug("ICMP Ping results: %s", mac_status)
        
        return mac_status
