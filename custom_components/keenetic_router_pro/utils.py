"""Utilities for Keenetic Router Pro integration."""
from typing import Any, Dict, Optional
from .const import DOMAIN


def get_main_device_info(
        title: str, 
        entry_id: str, 
        firmware_version: str, 
        model: str,
        host: str,
        ssl: bool = False,
        ndns_domain: Optional[str] = None,
    ) -> Dict[str, Any]:
    """Device info для главного роутера."""
    scheme = "https" if ssl else "http"

    if ndns_domain and ndns_domain.strip():
        # Убираем протокол если есть
        clean_domain = ndns_domain.replace("https://", "").replace("http://", "").split("/")[0]
        configuration_url = f"{scheme}://{clean_domain}"
    else:
        configuration_url = f"{scheme}://{host}"

    return {
        "identifiers": {(DOMAIN, entry_id)},
        "name": title,
        "manufacturer": "Keenetic",
        "model": model or "Controller",
        "sw_version": firmware_version,
        "configuration_url": configuration_url,
    }


def get_mesh_device_info(
    title: str,
    entry_id: str,
    node: Optional[Dict[str, Any]] = None,
    node_cid: Optional[str] = None,
    host: Optional[str] = None,
    ssl: bool = False,
    fqdn: str = None
) -> Dict[str, Any]:
    """Device info для Mesh-ноды (связано с главным роутером)."""
    if node and node_cid:
        node_name = node.get("name") or node.get("mac") or node_cid
        node_ip = node.get("ip") or host

        if fqdn and fqdn.strip():
            scheme = "https" if ssl else "http"
            configuration_url = f"{scheme}://{fqdn}"
        else:
            scheme = "https" if ssl else "http"
            configuration_url = f"{scheme}://{node_ip}" if node_ip else None

        return {
            "identifiers": {(DOMAIN, f"mesh_{node_cid}")},
            "name": node_name,
            "manufacturer": "Keenetic",
            "model": node.get("model") or "Extender",
            "sw_version": node.get("firmware"),
            "via_device": (DOMAIN, entry_id),
            "configuration_url": configuration_url,
        }
    
    # Fallback к главному устройству
    return get_main_device_info(title, entry_id, None, None, host, ssl)


def get_mesh_usb_device_info(
    title: str,
    entry_id: str,
    mesh_node_name: str,
    mesh_cid: Optional[str] = None,
    node_ip: Optional[str] = None,
    ssl: bool = False,
) -> Dict[str, Any]:
    """Device info для USB на Mesh-ноде."""
    if mesh_cid:
        return {
            "identifiers": {(DOMAIN, f"mesh_{mesh_cid}")},
            "name": mesh_node_name,
            "manufacturer": "Keenetic",
            "via_device": (DOMAIN, entry_id),
        }
    # Fallback к главному устройству
    return get_main_device_info(title, entry_id, None, None, node_ip, ssl)

def get_wan_device_info(
    title: str,
    entry_id: str,
    wan_id: str,
    description: Optional[str] = None,
    iface_type: Optional[str] = None,
    role_label: Optional[str] = None,
) -> Dict[str, Any]:
    """Device info for a single WAN interface.

    Each WAN appears in HA as its own sub-device under the main router,
    so the user can see one card per uplink with all its sensors grouped.
    """
    name_parts = []
    if description and description != wan_id:
        name_parts.append(description)
    else:
        name_parts.append(wan_id)
    if role_label:
        name_parts.append(f"({role_label})")
    device_name = " ".join(name_parts)

    return {
        "identifiers": {(DOMAIN, f"{entry_id}_wan_{wan_id}")},
        "name": f"{title} — {device_name}",
        "manufacturer": "Keenetic",
        "model": f"WAN ({iface_type})" if iface_type else "WAN",
        "via_device": (DOMAIN, entry_id),
    }


def get_client_device_info(
    entry_id: str,
    mac: str,
    label: str,
    client: Optional[Dict[str, Any]] = None,
    initial_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Device info для отслеживаемого клиента как отдельного устройства."""
    
    device_name = label
    manufacturer = None
    model = None
    if client:
        if client.get("hostname"):
            device_name = client.get("hostname")
        else:
            device_name = client.get("name", "").split(' - ')[0]

        ssdp = client.get("ssdp")
        if ssdp:
            if ssdp.get("manufacturer"):
                manufacturer = ssdp.get("manufacturer")

            if ssdp.get("model"):
                model = ssdp.get("model")
    
    ip_address = initial_ip
    if client and client.get("ip"):
        ip_address = client.get("ip")
    
    return {
        "identifiers": {(DOMAIN, f"client_{mac.replace(':', '_')}")},
        "name": device_name,
        "manufacturer": manufacturer,
        "model": model,
        "via_device": (DOMAIN, entry_id),
        "configuration_url": f"http://{ip_address}" if ip_address else None,
        "connections": {("mac", mac.upper())},
    }