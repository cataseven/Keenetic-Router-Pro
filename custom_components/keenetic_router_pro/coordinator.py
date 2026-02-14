"""DataUpdateCoordinator for Keenetic Router Pro."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import KeeneticClient
from .const import DOMAIN, FAST_SCAN_INTERVAL, PING_SCAN_INTERVAL

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

        # Interface verisini bir kez çek, tüm metotlara paylaştır
        interfaces = await self.client.async_get_interfaces()

        wifi = await self.client.async_get_wifi_networks(interfaces=interfaces)
        wireguard = await self.client.async_get_wireguard_status(interfaces=interfaces)
        vpn_tunnels = await self.client.async_get_vpn_tunnels(interfaces=interfaces)
        clients = await self.client.async_get_clients()
        
        # Yeni veriler
        wan_status = await self.client.async_get_wan_status(interfaces=interfaces)
        mesh_nodes = await self.client.async_get_mesh_nodes()
        traffic_stats = await self.client.async_get_traffic_stats(interfaces=interfaces)
        client_stats = await self.client.async_get_client_stats()
        host_policies = await self.client.async_get_host_policies()

        # Ana router USB
        usb_storage = await self.client.async_get_usb_storage()

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
            "system": system,
            "interfaces": interfaces,
            "wifi": wifi,
            "wireguard": wireguard,
            "vpn_tunnels": vpn_tunnels,
            "clients": clients,
            "wan_status": wan_status,
            "mesh_nodes": mesh_nodes,
            "traffic_stats": traffic_stats,
            "client_stats": client_stats,
            "host_policies": host_policies,
            "usb_storage": usb_storage,
            "mesh_usb": mesh_usb,
            "new_clients": new_macs,  # Yeni bağlanan MAC'ler
        }


class KeeneticPingCoordinator(DataUpdateCoordinator[dict[str, bool]]):
    """Coordinator for ICMP ping-based presence detection of tracked clients.
    
    Uses real ICMP ping (like Home Assistant's Ping integration) instead of
    router API to detect if a device is actually connected to the network.
    """

    # Ping configuration
    PING_COUNT = 3          # Gönderilecek ping sayısı
    PING_TIMEOUT = 1        # Her ping için timeout (saniye)
    PING_PRIVILEGED = False # Unprivileged mode (root gerektirmez)

    def __init__(
        self,
        hass: HomeAssistant,
        client: KeeneticClient,
        tracked_clients: list[dict[str, str]],
    ) -> None:
        """Initialize the ping coordinator.
        
        Args:
            hass: Home Assistant instance
            client: Keenetic API client (used for IP updates from router)
            tracked_clients: List of dicts with 'mac', 'ip', 'name' keys
        """
        super().__init__(
            hass,
            _LOGGER,
            name="keenetic_router_pro_ping",
            update_interval=timedelta(seconds=PING_SCAN_INTERVAL),
        )
        self.client = client
        self._tracked_clients = tracked_clients
        self._privileged: bool | None = None  # Will be determined on first ping
        
        # MAC -> IP mapping (güncellenebilir)
        self._mac_to_ip: dict[str, str] = {}
        for c in tracked_clients:
            mac = str(c.get("mac") or "").lower()
            ip = str(c.get("ip") or "")
            if mac and ip:
                self._mac_to_ip[mac] = ip

    def update_tracked_clients(self, tracked_clients: list[dict[str, str]]) -> None:
        """Update the list of tracked clients."""
        self._tracked_clients = tracked_clients
        self._mac_to_ip = {}
        for c in tracked_clients:
            mac = str(c.get("mac") or "").lower()
            ip = str(c.get("ip") or "")
            if mac and ip:
                self._mac_to_ip[mac] = ip

    def update_client_ip(self, mac: str, ip: str) -> None:
        """Update IP address for a specific client (dynamic IP support)."""
        mac_lower = mac.lower()
        if ip:
            self._mac_to_ip[mac_lower] = ip

    def get_tracked_macs(self) -> set[str]:
        """Return set of tracked MAC addresses."""
        return {str(c.get("mac") or "").lower() for c in self._tracked_clients if c.get("mac")}

    def get_client_info(self, mac: str) -> dict[str, str] | None:
        """Get client info by MAC address."""
        mac_lower = mac.lower()
        for c in self._tracked_clients:
            if str(c.get("mac") or "").lower() == mac_lower:
                return c
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
            
        except Exception as err:
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
            if isinstance(result, Exception):
                _LOGGER.debug("Ping exception for %s: %s", mac, result)
                mac_status[mac] = False
            else:
                mac_status[mac] = bool(result)
        
        _LOGGER.debug("ICMP Ping results: %s", mac_status)
        
        return mac_status
