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