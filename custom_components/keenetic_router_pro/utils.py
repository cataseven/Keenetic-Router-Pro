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

def get_client_device_info(
    entry_id: str,
    mac: str,
    label: str,
    client: Optional[Dict[str, Any]] = None,
    initial_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Device info для отслеживаемого клиента как отдельного устройства."""
    
    # Try to get better name from client data
    device_name = label
    if client:
        if client.get("name"):
            device_name = client.get("name")
        elif client.get("hostname"):
            device_name = client.get("hostname")
    
    # Determine manufacturer from MAC OUI
    manufacturer = _get_manufacturer_from_mac(mac)
    
    # Get model from client data if available
    model = None
    if client:
        model = client.get("device_type") or client.get("model")
    
    # Get firmware/OS version if available
    sw_version = None
    if client:
        sw_version = client.get("os_version") or client.get("firmware")
    
    # Get IP address
    ip_address = initial_ip
    if client and client.get("ip"):
        ip_address = client.get("ip")
    
    return {
        "identifiers": {(DOMAIN, f"client_{mac.replace(':', '_')}")},
        "name": device_name,
        "manufacturer": manufacturer,
        "model": model,
        "sw_version": sw_version,
        "via_device": (DOMAIN, entry_id),  # Links to main router
        "configuration_url": f"http://{ip_address}" if ip_address else None,
        "connections": {("mac", mac.upper())},
    }


def _get_manufacturer_from_mac(mac: str) -> str:
    """Try to determine manufacturer from MAC address OUI."""
    # Remove separators and get first 6 characters
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    
    # Common manufacturers (add more as needed)
    manufacturers = {
        "00037F": "Apple",
        "0010F3": "Apple",
        "0017F2": "Apple",
        "002370": "Apple",
        "00259E": "Apple",
        "00241E": "Apple",
        "007F5E": "Apple",
        "0024B2": "Dell",
        "0022B0": "Dell",
        "0013CE": "Dell",
        "0026B9": "Dell",
        "001BFC": "Samsung",
        "002577": "Samsung",
        "001EEC": "Samsung",
        "001F3B": "Samsung",
        "00221F": "Samsung",
        "002475": "Samsung",
        "AC1F6B": "Samsung",
        "0022A5": "Samsung",
        "00306E": "Google",
        "00409E": "Google",
        "007C2E": "Google",
        "001E6E": "Google",
        "0040E9": "Google",
        "FCB4E7": "Google",
        "B48B19": "Google",
        "001E0B": "Nokia",
        "0022B0": "Nokia",
        "0023E2": "Nokia",
        "0025B0": "Nokia",
        "003065": "Huawei",
        "0010C6": "Huawei",
        "002262": "Huawei",
        "001F3A": "Huawei",
        "00216A": "Xiaomi",
        "0022F4": "Xiaomi",
        "002433": "Xiaomi",
        "0025D5": "Xiaomi",
        "B8FF61": "Xiaomi",
        "002608": "Xiaomi",
        "0025B3": "Sony",
        "0025FE": "Sony",
        "0019C5": "LG",
        "001E66": "LG",
        "00226F": "LG",
    }
    
    return manufacturers.get(oui, "Unknown")