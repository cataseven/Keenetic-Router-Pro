"""Low-level async API client for Keenetic Router Pro integration (Basic Auth to /rci)."""

from __future__ import annotations

from typing import Any, Optional, Dict, List

import aiohttp
import async_timeout
import asyncio
import base64
import logging

from .const import DOMAIN

_LOGGER = logging.getLogger(f"custom_components.{DOMAIN}.api")

RCI_ROOT = "/rci"


class KeeneticApiError(Exception):
    """Base API error."""


class KeeneticAuthError(KeeneticApiError):
    """Authentication failed."""


class KeeneticClient:

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 100,
        ssl: bool = False,
        request_timeout: int = 15,
    ) -> None:
        self._host = host
        self._username = username
        self._password = password
        self._port = port
        self._ssl = ssl
        self._request_timeout = request_timeout

        scheme = "https" if ssl else "http"
        self._base = f"{scheme}://{host}:{port}"

        self._session: Optional[aiohttp.ClientSession] = None
        self._auth_header: Optional[Dict[str, str]] = None
        self._authenticated: bool = False


    async def async_start(self, session: aiohttp.ClientSession) -> None:
        """Attach an aiohttp session and authenticate."""
        self._session = session
        await self._async_authenticate()

    async def _async_authenticate(self) -> None:
        """Perform Basic auth against /rci/, like original ha_keenetic."""
        if self._session is None:
            raise KeeneticAuthError("ClientSession is not set")

        auth_string = base64.b64encode(
            f"{self._username}:{self._password}".encode()
        ).decode()
        headers = {"Authorization": f"Basic {auth_string}"}
        url = f"{self._base}{RCI_ROOT}/"

        _LOGGER.debug("Authenticating to Keenetic via %s", url)

        try:
            async with async_timeout.timeout(self._request_timeout):
                resp = await self._session.get(url, headers=headers)
        except aiohttp.ClientError as err:
            raise KeeneticAuthError(f"Auth connection failed: {err}") from err

        if resp.status != 200:
            text = await resp.text()
            raise KeeneticAuthError(
                f"Auth failed (status {resp.status}): {text}"
            )

        self._auth_header = headers
        self._authenticated = True
        _LOGGER.debug(
            "Authenticated to Keenetic router at %s:%s",
            self._host,
            self._port,
        )

    async def _ensure_auth(self) -> None:
        """Ensure we are authenticated before making an RCI call."""
        if not self._authenticated:
            await self._async_authenticate()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Dict[str, Any] | None = None,
        json: Any | None = None,
        allow_text: bool = False,
    ) -> Any:
        """Perform a raw HTTP request to Keenetic."""
        if self._session is None:
            raise KeeneticApiError("ClientSession is not set")

        await self._ensure_auth()

        url = f"{self._base}{path}"
        headers: Dict[str, str] = dict(self._auth_header or {})

        _LOGGER.debug(
            "Keenetic request: %s %s params=%s json=%s",
            method,
            url,
            params,
            json,
        )

        try:
            async with async_timeout.timeout(self._request_timeout):
                resp = await self._session.request(
                    method,
                    url,
                    params=params,
                    json=json,
                    headers=headers,
                )
        except aiohttp.ClientError as err:
            raise KeeneticApiError(f"Connection error: {err}") from err

        # Basic auth hatalıysa yine 401 alırız
        if resp.status == 401:
            text = await resp.text()
            _LOGGER.error("Keenetic Basic auth rejected: %s", text)
            self._authenticated = False
            raise KeeneticAuthError(f"Basic auth rejected: {text}")

        if resp.status >= 400:
            text = await resp.text()
            raise KeeneticApiError(
                f"HTTP error {resp.status} for {path}: {text}"
            )

        if allow_text:
            ctype = resp.headers.get("Content-Type", "")
            if "application/json" in ctype:
                return await resp.json()
            return await resp.text()

        return await resp.json()

    async def _rci_get(
        self,
        subpath: str,
        *,
        params: Dict[str, Any] | None = None,
    ) -> Any:
        """GET /rci/<subpath>."""
        path = f"{RCI_ROOT}/{subpath.lstrip('/')}"
        return await self._request("GET", path, params=params)

    async def _rci_post(
        self,
        subpath: str,
        json: Any,
        *,
        allow_text: bool = False,
    ) -> Any:
        """POST /rci/<subpath>."""
        path = f"{RCI_ROOT}/{subpath.lstrip('/')}"
        return await self._request("POST", path, json=json, allow_text=allow_text)

    async def _rci_parse(self, command: str) -> Any:
        """Execute a CLI-like command via /rci/parse."""
        # JSON body sadece string: "interface Wireguard0 up"
        return await self._rci_post("parse", command, allow_text=True)

    def _normalize_interfaces(self, raw: Any) -> List[Dict[str, Any]]:
        """Raw /rci/show/interface çıktısını evrensel listeye çevir."""
        if isinstance(raw, dict):
            # {"GigabitEthernet0": {...}, "WifiMaster0/AccessPoint0": {...}}
            return [v for v in raw.values() if isinstance(v, dict)]
        if isinstance(raw, list):
            # [ {...}, {...} ]
            return [v for v in raw if isinstance(v, dict)]
        return []

    async def async_ping_ip(self, ip_address: str, timeout: float = 2.0) -> bool:
        """Ping an IP address using the router's ping functionality.
        
        Returns True if the host is reachable, False otherwise.
        """
        try:

            result = await self._rci_parse(f"ip ping {ip_address} count 1")
            
            if result is None:
                return False
            
            result_str = str(result).lower()

            if "1 received" in result_str or "bytes from" in result_str:
                return True
            
            # Check for failure patterns
            if "0 received" in result_str or "100% packet loss" in result_str:
                return False

            if "timeout" not in result_str and "unreachable" not in result_str:
                return True
            
            return False
            
        except Exception as err:
            _LOGGER.debug("Ping to %s failed: %s", ip_address, err)
            return False

    async def async_ping_multiple(
        self, 
        ip_addresses: List[str], 
        timeout: float = 2.0
    ) -> Dict[str, bool]:
        """Ping multiple IP addresses concurrently.
        
        Returns a dict mapping IP address to reachability status.
        """
        if not ip_addresses:
            return {}
        
        tasks = [self.async_ping_ip(ip, timeout) for ip in ip_addresses]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        ping_results: Dict[str, bool] = {}
        for ip, result in zip(ip_addresses, results):
            if isinstance(result, Exception):
                ping_results[ip] = False
            else:
                ping_results[ip] = bool(result)
        
        return ping_results

    async def async_get_system_info(self) -> Dict[str, Any]:
        """Return basic system info: hostname, version, cpu, memory, uptime, etc."""
        data = await self._rci_get("show/system")
        return data or {}

    async def async_get_interfaces(self) -> Dict[str, Any]:
        """Return raw interfaces dictionary from /rci/show/interface."""
        data = await self._rci_get("show/interface")
        return data or {}

    async def async_get_interface_stat(self, name: str) -> Dict[str, Any]:
        """Return statistics (traffic, speed) for a specific interface."""
        return await self._rci_get("show/interface/stat", params={"name": name}) or {}

    async def async_get_clients(self) -> List[Dict[str, Any]]:

        last_data: Any = None

        for subpath in ("show/ip/hotspot/host", "ip/hotspot/host"):
            try:
                data = await self._rci_get(subpath)
                last_data = data
            except Exception:
                continue

            hosts: Any
            if isinstance(data, list):
                hosts = data
            elif isinstance(data, dict):
                hosts = data.get("hosts") or data.get("host") or data.get("items") or []
            else:
                hosts = []

            if isinstance(hosts, dict):
                items = [v for v in hosts.values() if isinstance(v, dict)]
            elif isinstance(hosts, list):
                items = [v for v in hosts if isinstance(v, dict)]
            else:
                items = []

            if items:
                return items

        _LOGGER.debug("No clients parsed from hotspot host response: %s", last_data)
        return []


    async def async_get_wireguard_status(
        self, interfaces: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Return WireGuard interfaces and their status."""
        if interfaces is None:
            interfaces = await self.async_get_interfaces()
        iface_list = self._normalize_interfaces(interfaces)

        profiles: Dict[str, Any] = {}

        for item in iface_list:
            itype = (item.get("type") or "").lower()
            traits = [t.lower() for t in item.get("traits", []) if isinstance(t, str)]
            name = (
                item.get("id")
                or item.get("interface-name")
                or item.get("name")
                or item.get("ifname")
            )
            if not name:
                continue

            is_wg = itype == "wireguard" or "wireguard" in "".join(traits)
            if not is_wg:
                continue

            wg_info = item.get("wireguard") or {}
            description = item.get("description") or name 

            remote = None
            rx_val = wg_info.get("rxbytes") or item.get("rxbytes")
            tx_val = wg_info.get("txbytes") or item.get("txbytes")

            peer = wg_info.get("peer")

            if isinstance(peer, list) and peer:
                p = peer[0]
                if remote is None:
                    remote = p.get("remote-endpoint-address")
                if rx_val is None:
                    rx_val = p.get("rxbytes")
                if tx_val is None:
                    tx_val = p.get("txbytes")
            elif isinstance(peer, dict):
                if remote is None:
                    remote = peer.get("remote-endpoint-address")
                if rx_val is None:
                    rx_val = peer.get("rxbytes")
                if tx_val is None:
                    tx_val = peer.get("txbytes")

            profiles[name] = {

                "label": description,
                "enabled": str(item.get("state", "")).lower() == "up",
                "state": item.get("state"),
                "address": item.get("address"),
                "remote": remote,
                "uptime": item.get("uptime"),
                "rx": rx_val,
                "tx": tx_val,
                "rxbytes": rx_val,
                "txbytes": tx_val,
            }

        return {"profiles": profiles}


    async def async_get_wifi_networks(
        self, interfaces: Dict[str, Any] | None = None
    ) -> List[Dict[str, Any]]:


        if interfaces is None:
            interfaces = await self.async_get_interfaces()
        iface_list = self._normalize_interfaces(interfaces)

        bridge_labels: Dict[str, str] = {}
        for item in iface_list:
            itype = (item.get("type") or "").lower()
            if itype != "bridge":
                continue

            bid = item.get("id") or item.get("interface-name")
            if not bid:
                continue

            label = (
                item.get("interface-name")
                or item.get("description")
                or bid
            )
            bridge_labels[str(bid)] = str(label)

        ap_items: List[Dict[str, Any]] = []
        for item in iface_list:
            raw_id = (
                item.get("id")
                or item.get("interface-name")
                or item.get("name")
                or item.get("ifname")
            )
            if not raw_id:
                continue

            itype = (item.get("type") or "").lower()
            traits = [t.lower() for t in item.get("traits", []) if isinstance(t, str)]
            id_lower = raw_id.lower()

            is_ap = (
                "accesspoint" in id_lower
                or itype == "accesspoint"
                or ("wifi" in "".join(traits) and "accesspoint" in "".join(traits))
            )
            if not is_ap:
                continue

            ssid = (item.get("ssid") or "").strip()
            group = str(item.get("group") or "").strip()
            if not ssid and not group:
                continue

            clone = dict(item)
            clone["__id"] = raw_id
            ap_items.append(clone)

        groups: Dict[str, Dict[str, Any]] = {}
        for item in ap_items:
            raw_id = item["__id"]
            ssid = (item.get("ssid") or "").strip()
            group = str(item.get("group") or "").strip()
            base_id = raw_id.split("/")[0]

            group_key = group or ssid or base_id

            g = groups.setdefault(
                group_key,
                {
                    "ssid": ssid,
                    "group": group,
                    "aps": [],
                },
            )

            if not g["ssid"]:
                if ssid:
                    g["ssid"] = ssid
                elif group and group in bridge_labels:
                    g["ssid"] = bridge_labels[group]
                elif group:
                    g["ssid"] = group

            g["aps"].append(item)

        wifi_networks: List[Dict[str, Any]] = []

        for g in groups.values():
            logical_name = (g["ssid"] or "").strip()
            group = g["group"]

            if not logical_name:
                if group and group in bridge_labels:
                    logical_name = bridge_labels[group]
                elif group:
                    logical_name = group
                else:
                    logical_name = "Wi-Fi"

            per_band: Dict[str, Dict[str, Any]] = {}

            for ap in g["aps"]:
                raw_id = ap["__id"]
                band = str(ap.get("band") or "").strip()

                if not band:
                    base_id = raw_id.split("/")[0].lower()
                    chan = str(ap.get("channel") or "")
                    if "wifimaster0" in base_id:
                        band = "2.4"
                    elif "wifimaster1" in base_id:
                        band = "5"
                    elif chan:
                        try:
                            ch = int(chan)
                            band = "2.4" if 1 <= ch <= 14 else "5"
                        except ValueError:
                            pass

                if band:
                    b_lower = band.lower()
                    if "2.4" in b_lower or b_lower == "2":
                        band_label = "2.4 GHz"
                    elif "5" in b_lower:
                        band_label = "5 GHz"
                    else:
                        band_label = band
                else:
                    band_label = ""

                key = band_label or "default"
                if key in per_band:
                    continue
                per_band[key] = ap

            for band_label, ap in per_band.items():
                raw_id = ap["__id"]
                state = str(ap.get("state", "")).lower()
                enabled = state == "up"

                vis_name = logical_name
                if band_label:
                    vis_name = f"{logical_name} {band_label}"

                net: Dict[str, Any] = {
                    "id": raw_id,          
                    "name": vis_name,      
                    "ssid": logical_name,
                    "band": band_label,
                    "enabled": enabled,
                    "state": ap.get("state"),
                    "group": group or None,
                    "channel": ap.get("channel"),
                    "tx_power": ap.get("tx-power") or ap.get("tx_power"),
                }

                for k in list(net.keys()):
                    if any(
                        pat in k.lower()
                        for pat in ("password", "pass", "psk", "wpa", "key", "secret")
                    ):
                        net.pop(k, None)

                wifi_networks.append(net)

        return wifi_networks




    async def async_set_wifi_enabled(self, interface_name: str, enabled: bool) -> None:
        """Enable or disable a Wi-Fi interface via RCI parse."""
        cmd = f"interface {interface_name} {'up' if enabled else 'down'}"
        _LOGGER.debug("Set Wi-Fi %s enabled=%s via: %s", interface_name, enabled, cmd)
        await self._rci_parse(cmd)

    async def async_set_wireguard_enabled(self, interface_name: str, enabled: bool) -> None:
        """Enable or disable a WireGuard interface via RCI parse."""
        cmd = f"interface {interface_name} {'up' if enabled else 'down'}"
        _LOGGER.debug(
            "Set WireGuard %s enabled=%s via: %s",
            interface_name,
            enabled,
            cmd,
        )
        await self._rci_parse(cmd)

    async def async_reboot(self) -> None:
        """Reboot the router via 'system reboot' command."""
        cmd = "system reboot"
        _LOGGER.warning("Sending router reboot command via RCI parse")
        await self._rci_parse(cmd)

    async def async_get_vpn_tunnels(
        self, interfaces: Dict[str, Any] | None = None
    ) -> dict[str, dict[str, Any]]:
        """Auto-discover VPN-like interfaces (WireGuard, OpenVPN, IPsec, ...).

        Returns:
            {
              "profiles": {
                 "Wireguard0": {...},
                 "Wireguard1": {...},
                 "OpenVpn0": {...},
                 ...
              }
            }
        """
        if interfaces is None:
            interfaces = await self.async_get_interfaces()
        iface_list = self._normalize_interfaces(interfaces)

        VPN_TYPES = {
            "wireguard",
            "openvpn",
            "ipsec",
            "l2tp",
            "pptp",
            "zerotier",
            "tor",
        }

        profiles: dict[str, dict[str, Any]] = {}

        for item in iface_list:
            itype = str(item.get("type") or "").lower()
            if itype not in VPN_TYPES:
                continue

            iface_id = (
                item.get("id")
                or item.get("interface-name")
                or item.get("name")
            )
            if not iface_id:
                continue

            label = (
                item.get("description")
                or item.get("interface-name")
                or iface_id
            )

            state = str(item.get("state") or "").lower()
            summary = item.get("summary") or {}
            layer = summary.get("layer") or {}
            conf = str(layer.get("conf") or "").lower()

            enabled = not (conf == "disabled" or state == "down")

            profiles[str(iface_id)] = {
                "id": iface_id,
                "type": item.get("type") or itype,
                "label": str(label),
                "enabled": enabled,
                "state": item.get("state"),
            }

        return {"profiles": profiles}

    async def async_get_wan_status(
        self, interfaces: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Get WAN interface status including external IP address.
        
        PPPoE bağlantısı varsa oradan, yoksa WAN interface'inden IP alır.
        """
        if interfaces is None:
            interfaces = await self.async_get_interfaces()
        iface_list = self._normalize_interfaces(interfaces)

        # Önce PPPoE ara (öncelikli)
        for iface in iface_list:
            itype = str(iface.get("type") or "").lower()
            state = str(iface.get("state") or "").lower()
            
            if itype == "pppoe" and state == "up":
                return {
                    "status": "up",
                    "ip": iface.get("address"),
                    "interface": iface.get("id") or iface.get("interface-name"),
                    "uptime": iface.get("uptime"),
                    "gateway": iface.get("remote"),
                    "type": "pppoe",
                }

        WAN_KEYWORDS = ("wan", "internet", "isp")

        for iface in iface_list:
            state = str(iface.get("state") or "").lower()
            
            name_fields = [
                iface.get("name"),
                iface.get("ifname"),
                iface.get("id"),
                iface.get("interface-name"),
                iface.get("description"),
                iface.get("type"),
            ]
            name_joined = " ".join(str(v) for v in name_fields if v).lower()

            if state == "up" and any(k in name_joined for k in WAN_KEYWORDS):
                address = iface.get("address")
                if isinstance(address, list) and address:
                    wan_ip = address[0].get("address") if isinstance(address[0], dict) else str(address[0])
                elif isinstance(address, str):
                    wan_ip = address
                else:
                    wan_ip = iface.get("ip") or iface.get("ipv4") or None

                return {
                    "status": "up",
                    "ip": wan_ip,
                    "interface": iface.get("id") or iface.get("interface-name"),
                    "uptime": iface.get("uptime"),
                    "gateway": iface.get("gateway"),
                    "type": "ethernet",
                }

        return {"status": "down", "ip": None}


    async def async_get_mesh_nodes(self) -> List[Dict[str, Any]]:
        """Get mesh/extender nodes status from mws/member endpoint.
        
        Bu endpoint tüm mesh üyelerini detaylı bilgileriyle döndürür.
        """
        nodes: List[Dict[str, Any]] = []

        try:
            data = await self._rci_get("show/mws/member")
            
            if not data or not isinstance(data, list):
                return nodes

            for member in data:
                cid = member.get("cid")
                if not cid:
                    continue

                mac = member.get("mac")
                system_info = member.get("system", {})
                rci_info = member.get("rci", {})
                
                is_connected = (
                    rci_info.get("errors", 0) == 0 
                    or member.get("internet-available", False)
                )

                nodes.append({
                    "id": cid,
                    "cid": cid,
                    "mac": mac,
                    "ip": member.get("ip"),
                    "name": member.get("known-host") or member.get("model") or mac,
                    "model": member.get("model"),
                    "mode": member.get("mode"), 
                    "hw_id": member.get("hw_id"),
                    "connected": is_connected,
                    "state": "up" if is_connected else "down",
                    "uptime": system_info.get("uptime"),
                    "cpuload": system_info.get("cpuload"),
                    "memory": system_info.get("memory"),
                    "firmware": member.get("fw"),
                    "firmware_available": member.get("fw-available"),
                    "associations": member.get("associations", 0), 
                    "rci_errors": rci_info.get("errors", 0),
                })

        except Exception as err:
            _LOGGER.debug("Error getting mesh nodes from mws/member: %s", err)
            return await self._get_mesh_nodes_from_clients()

        return nodes

    async def _get_mesh_nodes_from_clients(self) -> List[Dict[str, Any]]:
        """Fallback: Get mesh nodes from client list if mws/member fails."""
        clients = await self.async_get_clients()
        nodes: List[Dict[str, Any]] = []

        for client in clients:
            system_mode = str(client.get("system-mode") or "").lower()
            if system_mode not in ("extender", "repeater"):
                continue

            mac = client.get("mac")
            if not mac:
                continue

            is_active = bool(client.get("active", False))

            nodes.append({
                "id": mac,
                "cid": None, 
                "mac": mac,
                "ip": client.get("ip"),
                "name": client.get("name") or client.get("hostname") or mac,
                "mode": system_mode,
                "connected": is_active,
                "state": "up" if is_active else "down",
                "uptime": client.get("uptime"),
                "firmware": client.get("firmware"),
            })

        return nodes

    async def async_reboot_mesh_node(self, cid: str) -> None:
        """Reboot a specific mesh/extender node by CID (component ID).
        
        Command format: mws member {cid} reboot
        """
        _LOGGER.warning("Sending reboot command to mesh node cid=%s", cid)
        
        cmd = f"mws member {cid} reboot"
        await self._rci_parse(cmd)

    async def async_get_mesh_node_usb(
        self, node_ip: str, node_name: str = "", node_cid: str = ""
    ) -> List[Dict[str, Any]]:
        """Get USB storage info directly from a mesh/extender node.
        
        Mesh member'lar kendi RCI API'larına sahip ve controller ile
        aynı credentials'ı paylaşır. Doğrudan member IP'sine bağlanıp
        POST /rci/system/usb ile USB bilgisini alırız.
        """
        devices: List[Dict[str, Any]] = []

        if not self._session or not self._auth_header or not node_ip:
            return devices

        scheme = "https" if self._ssl else "http"
        url = f"{scheme}://{node_ip}:{self._port}{RCI_ROOT}/system/usb"

        try:
            async with async_timeout.timeout(self._request_timeout):
                resp = await self._session.post(
                    url,
                    json={},
                    headers=self._auth_header,
                )

            if resp.status == 401:
                _LOGGER.debug(
                    "Auth rejected by mesh node %s (%s), "
                    "member may use different credentials",
                    node_name, node_ip,
                )
                return devices

            if resp.status >= 400:
                _LOGGER.debug(
                    "Mesh node %s (%s) USB endpoint returned %s",
                    node_name, node_ip, resp.status,
                )
                return devices

            ctype = resp.headers.get("Content-Type", "")
            if "application/json" not in ctype:
                # JSON değilse (text/html vb.) geçersiz yanıt
                return devices

            data = await resp.json()

            if not data:
                return devices

            _LOGGER.debug(
                "Mesh node %s (%s) USB response: %s",
                node_name, node_ip, data,
            )

            # Parse - response dict veya list olabilir
            if isinstance(data, dict):
                port_list = data.get("port")
                if isinstance(port_list, list):
                    for port_info in port_list:
                        if isinstance(port_info, dict):
                            dev = self._parse_usb_device(
                                port_info,
                                f"mesh_{node_cid or node_ip}_usb",
                            )
                            if dev:
                                dev["mesh_cid"] = node_cid
                                dev["mesh_node_ip"] = node_ip
                                devices.append(dev)
                else:
                    for usb_id, usb_info in data.items():
                        if not isinstance(usb_info, dict):
                            continue
                        dev = self._parse_usb_device(
                            usb_info,
                            f"mesh_{node_cid or node_ip}_{usb_id}",
                        )
                        if dev:
                            dev["mesh_cid"] = node_cid
                            dev["mesh_node_ip"] = node_ip
                            devices.append(dev)

            elif isinstance(data, list):
                for usb_info in data:
                    if not isinstance(usb_info, dict):
                        continue
                    dev = self._parse_usb_device(
                        usb_info,
                        f"mesh_{node_cid or node_ip}_usb",
                    )
                    if dev:
                        dev["mesh_cid"] = node_cid
                        dev["mesh_node_ip"] = node_ip
                        devices.append(dev)

        except asyncio.TimeoutError:
            _LOGGER.debug(
                "Timeout getting USB from mesh node %s (%s)",
                node_name, node_ip,
            )
        except Exception as err:
            _LOGGER.debug(
                "Could not get USB from mesh node %s (%s): %s",
                node_name, node_ip, err,
            )

        return devices

    # -------------------------------------------------------------------------
    # Traffic Statistics
    # -------------------------------------------------------------------------

    async def async_get_traffic_stats(
        self, interfaces: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        """Get traffic statistics (speed, totals).
        
        Args:
            interfaces: Pre-fetched interfaces data to avoid duplicate API calls.
        """
        stats: Dict[str, Any] = {
            "download_speed": 0.0,  
            "upload_speed": 0.0,    
            "total_rx": 0,          
            "total_tx": 0,          
        }

        try:
            if interfaces is None:
                interfaces = await self.async_get_interfaces()
            iface_list = self._normalize_interfaces(interfaces)

            WAN_KEYWORDS = ("wan", "internet", "pppoe", "isp")

            for iface in iface_list:
                name_fields = [
                    iface.get("name"),
                    iface.get("ifname"),
                    iface.get("id"),
                    iface.get("interface-name"),
                    iface.get("description"),
                    iface.get("type"),
                ]
                name_joined = " ".join(str(v) for v in name_fields if v).lower()
                state = str(iface.get("state") or "").lower()

                if state == "up" and any(k in name_joined for k in WAN_KEYWORDS):
                    # Traffic counters
                    stats["total_rx"] = iface.get("rxbytes") or iface.get("rx-bytes") or 0
                    stats["total_tx"] = iface.get("txbytes") or iface.get("tx-bytes") or 0
                    
                    # Speed (bits per second -> MB/s)
                    rx_speed = iface.get("rx-speed") or iface.get("rxspeed") or 0
                    tx_speed = iface.get("tx-speed") or iface.get("txspeed") or 0
                    stats["download_speed"] = round(float(rx_speed) / 8 / 1024 / 1024, 2)
                    stats["upload_speed"] = round(float(tx_speed) / 8 / 1024 / 1024, 2)
                    break

        except Exception as err:
            _LOGGER.debug("Error getting traffic stats: %s", err)

        return stats

    async def async_get_usb_storage(self) -> List[Dict[str, Any]]:
        """Get USB storage devices information.

        Primary: POST /rci/system/usb
        Fallback: GET /rci/show/media (+ optional GET /rci/show/usb for extra attrs)

        Some Keenetic firmwares do NOT expose useful data via system/usb, while
        show/media does. This keeps HA entities alive without log spam.
        """
        devices: List[Dict[str, Any]] = []

        # 1) Try system/usb first (kept for compatibility)
        try:
            data = await self._rci_post("system/usb", {})
            devices = self._parse_system_usb_response(data)
        except Exception as err:
            _LOGGER.debug("system/usb failed: %s", err)

        # 2) If empty, fallback to show/media (+show/usb)
        if not devices:
            try:
                devices = await self._parse_show_media_usb()
            except Exception as err:
                _LOGGER.debug("show/media fallback failed: %s", err)

        return devices

    def _parse_system_usb_response(self, data: Any) -> List[Dict[str, Any]]:
        """Parse /rci/system/usb response into a normalized list."""
        devices: List[Dict[str, Any]] = []
        if not data:
            return devices

        # Yanıt dict ise: {"USB0": {...}, "USB1": {...}} veya {"port": [...]}
        if isinstance(data, dict):
            port_list = data.get("port")
            if isinstance(port_list, list):
                for port_info in port_list:
                    if not isinstance(port_info, dict):
                        continue
                    device = self._parse_usb_device(port_info, port_info.get("id") or "usb")
                    if device:
                        devices.append(device)
            else:
                for usb_id, usb_info in data.items():
                    if not isinstance(usb_info, dict):
                        continue
                    device = self._parse_usb_device(usb_info, usb_id)
                    if device:
                        devices.append(device)

        elif isinstance(data, list):
            for usb_info in data:
                if not isinstance(usb_info, dict):
                    continue
                device = self._parse_usb_device(usb_info, usb_info.get("id") or "usb")
                if device:
                    devices.append(device)

        return devices

    async def _parse_show_media_usb(self) -> List[Dict[str, Any]]:
        """Parse USB storage via show/media (and enrich via show/usb when available)."""
        media_raw = await self._rci_get("show/media")
        usb_raw = None
        try:
            usb_raw = await self._rci_get("show/usb")
        except Exception:
            usb_raw = None

        media_map: Dict[str, Dict[str, Any]] = {}
        if isinstance(media_raw, dict):
            media_map = {k: v for k, v in media_raw.items() if isinstance(v, dict)}

        usb_map: Dict[str, Dict[str, Any]] = {}
        if isinstance(usb_raw, dict):
            device_block = usb_raw.get("device")
            if isinstance(device_block, dict):
                usb_map = {k: v for k, v in device_block.items() if isinstance(v, dict)}

        devices: List[Dict[str, Any]] = []
        for dev_id, info in media_map.items():
            device = self._parse_show_media_device(dev_id, info, usb_map.get(dev_id))
            if device:
                devices.append(device)

        return devices

    def _to_int(self, v: Any, default: int = 0) -> int:
        """Convert Keenetic numeric fields which may arrive as strings."""
        if v is None:
            return default
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, (int, float)):
            return int(v)
        try:
            s = str(v).strip()
            if s == "":
                return default
            # Allow e.g. "30765219840"
            return int(float(s))
        except Exception:
            return default

    def _parse_show_media_device(
        self,
        dev_id: str,
        media_info: Dict[str, Any],
        usb_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any] | None:
        """Normalize show/media (+show/usb) device into our usb_storage schema."""
        if not media_info:
            return None

        # Partitions are usually the best source of size/free
        partitions = media_info.get("partition") or []
        part0: Dict[str, Any] | None = None
        if isinstance(partitions, list) and partitions:
            p = partitions[0]
            if isinstance(p, dict):
                part0 = p

        total = self._to_int((part0 or {}).get("total")) or self._to_int(media_info.get("size"))
        free = self._to_int((part0 or {}).get("free"))
        used = max(total - free, 0) if (total and free is not None) else self._to_int((part0 or {}).get("used"))

        filesystem = (part0 or {}).get("fstype") or media_info.get("fstype") or media_info.get("filesystem")
        label = (part0 or {}).get("label") or media_info.get("label") or media_info.get("product") or dev_id

        # Enrich from show/usb (port, power-control, etc.)
        port = None
        power_control = None
        usb_version = None
        if isinstance(usb_info, dict):
            port = usb_info.get("port")
            power_control = usb_info.get("power-control")
            usb_version = usb_info.get("usb-version")

        # Media block also has usb {port, version}
        usb_block = media_info.get("usb")
        if isinstance(usb_block, dict):
            port = port or usb_block.get("port")
            usb_version = usb_version or usb_block.get("version")

        return {
            "id": dev_id,
            "label": label,
            "vendor": media_info.get("manufacturer") or (usb_info or {}).get("manufacturer"),
            "model": media_info.get("product") or (usb_info or {}).get("product"),
            "serial": media_info.get("serial") or (usb_info or {}).get("serial"),
            "total": total,
            "used": used,
            "free": free,
            "filesystem": filesystem,
            "state": (part0 or {}).get("state") or media_info.get("state"),
            "type": media_info.get("bus") or "usb",
            # Extras (kept as attrs, harmless for existing UI)
            "port": port,
            "usb_version": usb_version,
            "ejectable": media_info.get("ejectable"),
            "power_control": power_control,
            "uuid": (part0 or {}).get("uuid"),
        }

    def _parse_usb_device(self, info: Dict[str, Any], fallback_id: str) -> Dict[str, Any] | None:
        """Parse a single USB device entry from /rci/system/usb response."""
        if not info:
            return None

        # Partition bilgileri
        partitions = info.get("partition") or info.get("partitions") or {}
        total_size = 0
        used_size = 0
        free_size = 0

        part_items: list = []
        if isinstance(partitions, dict):
            part_items = [v for v in partitions.values() if isinstance(v, dict)]
        elif isinstance(partitions, list):
            part_items = [v for v in partitions if isinstance(v, dict)]

        for p in part_items:
            total_size += p.get("size", 0)
            used_size += p.get("used", 0)
            free_size += p.get("free", p.get("available", 0))

        # Partition yoksa üst seviye bilgileri kullan
        if total_size == 0:
            total_size = info.get("size", 0)
            used_size = info.get("used", 0)
            free_size = info.get("free", info.get("available", 0))

        device_id = info.get("id") or info.get("name") or fallback_id

        return {
            "id": device_id,
            "label": info.get("label") or info.get("description") or info.get("model") or device_id,
            "vendor": info.get("vendor") or info.get("manufacturer"),
            "model": info.get("model") or info.get("product"),
            "serial": info.get("serial"),
            "total": total_size,
            "used": used_size,
            "free": free_size,
            "filesystem": info.get("filesystem") or info.get("fs"),
            "state": info.get("state") or info.get("status"),
            "type": info.get("type"),
        }


    async def async_get_client_stats(self) -> Dict[str, Any]:
        """Get connected/disconnected client counts and per-AP stats.
        
        Extender/repeater cihazları client sayısından çıkarılır.
        """
        clients = await self.async_get_clients()
        
        connected = 0
        disconnected = 0
        per_ap: Dict[str, int] = {}
        extenders: List[Dict[str, Any]] = []

        for client in clients:
            system_mode = str(client.get("system-mode") or "").lower()
            if system_mode in ("extender", "repeater"):
                extenders.append({
                    "mac": client.get("mac"),
                    "ip": client.get("ip"),
                    "name": client.get("name") or client.get("hostname") or client.get("mac"),
                    "mode": system_mode,
                    "active": client.get("active", False),
                    "uptime": client.get("uptime"),
                    "firmware": client.get("firmware"),
                    "description": client.get("description"),
                    "http_host": client.get("http-host"),
                })
                continue  
            
            is_active = False
            if "active" in client:
                value = client.get("active")
                if isinstance(value, bool):
                    is_active = value
                elif isinstance(value, str):
                    is_active = value.lower() in ("true", "yes", "1", "up", "online")
                else:
                    is_active = bool(value)
            elif "link" in client:
                is_active = str(client.get("link") or "").lower() == "up"

            if is_active:
                connected += 1
            else:
                disconnected += 1

            iface = client.get("interface")
            if isinstance(iface, dict):
                ap_name = iface.get("name") or iface.get("id") or "Unknown"
            else:
                ap_name = str(iface) if iface else "Unknown"

            ssid = client.get("ssid")
            if ssid:
                ap_name = str(ssid)

            if is_active:
                per_ap[ap_name] = per_ap.get(ap_name, 0) + 1

        return {
            "connected": connected,
            "disconnected": disconnected,
            "total": connected + disconnected, 
            "per_ap": per_ap,
            "extenders": extenders,
            "extender_count": len(extenders),
        }

    async def async_get_policies(self) -> Dict[str, str]:
        """Get available connection policies.
        
        Returns:
            Dict mapping policy_id to description
            e.g. {"Policy0": "VPN", "Policy1": "Smart Home", ...}
        """
        try:
            # Doğru endpoint: GET /rci/ip/policy
            data = await self._rci_get("ip/policy")
            if not data or not isinstance(data, dict):
                return {}
            
            policies = {}
            for policy_id, policy_data in data.items():
                if isinstance(policy_data, dict):
                    desc = policy_data.get("description") or policy_id
                    policies[policy_id] = str(desc)
            
            return policies
        except Exception as err:
            _LOGGER.debug("Error getting policies: %s", err)
            return {}

    async def async_get_host_policies(self) -> Dict[str, Dict[str, Any]]:
        """Get policy assignments for all hosts.
        
        Returns:
            Dict mapping MAC to policy info
            e.g. {"aa:bb:cc:dd:ee:ff": {"policy": "Policy1", "access": "permit"}, ...}
        """
        try:
            # Doğru endpoint: GET /rci/ip/hotspot/host
            data = await self._rci_get("ip/hotspot/host")
            if not data:
                return {}
            
            # Liste veya dict gelebilir
            hosts: list = []
            if isinstance(data, list):
                hosts = data
            elif isinstance(data, dict):
                hosts = data.get("host") or data.get("hosts") or []
                if isinstance(hosts, dict):
                    hosts = list(hosts.values())
            
            host_policies = {}
            for host in hosts:
                if not isinstance(host, dict):
                    continue
                mac = str(host.get("mac") or "").lower()
                if mac:
                    host_policies[mac] = {
                        "policy": host.get("policy"), 
                        "access": host.get("access"), 
                    }
            
            return host_policies
        except Exception as err:
            _LOGGER.debug("Error getting host policies: %s", err)
            return {}

    async def async_set_client_policy(self, mac: str, policy: str) -> None:
        """Set connection policy for a client.
        
        Args:
            mac: Client MAC address
            policy: Policy ID (e.g. "Policy0", "Policy1") or "deny"/"default"
        """
        mac_clean = mac.lower().replace("-", ":")
        
        if policy.lower() == "deny":
            cmd = f"ip hotspot host {mac_clean} deny"
            _LOGGER.debug("Blocking client %s", mac_clean)
            await self._rci_parse(cmd)
        elif policy.lower() in ("default", "permit", ""):

            cmd = f"no ip hotspot host {mac_clean} policy"
            _LOGGER.debug("Removing policy from client %s", mac_clean)
            await self._rci_parse(cmd)

            cmd = f"ip hotspot host {mac_clean} permit"
            await self._rci_parse(cmd)
        else:

            cmd = f"ip hotspot host {mac_clean} policy {policy}"
            _LOGGER.debug("Setting client %s policy to %s", mac_clean, policy)
            await self._rci_parse(cmd)
        
        await self._rci_parse("system configuration save")

    async def async_block_client(self, mac: str) -> None:
        """Block a client's internet access."""
        await self.async_set_client_policy(mac, "deny")

    async def async_unblock_client(self, mac: str) -> None:
        """Unblock a client's internet access."""
        await self.async_set_client_policy(mac, "default")