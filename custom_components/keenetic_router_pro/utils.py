"""Utilities for Keenetic Router Pro integration."""
from typing import Any, Dict, Optional
from .const import DOMAIN


def get_main_device_info(title: str, entry_id: str, firmware_version: str, model: str) -> Dict[str, Any]:
    """Device info для главного роутера."""
    return {
        "identifiers": {(DOMAIN, entry_id)},
        "name": title,
        "manufacturer": "Keenetic",
        "model": model or "Controller",
        "sw_version": firmware_version,
    }


def get_mesh_device_info(
    title: str,
    entry_id: str,
    node: Optional[Dict[str, Any]] = None,
    node_cid: Optional[str] = None,
) -> Dict[str, Any]:
    """Device info для Mesh-ноды (связано с главным роутером)."""
    if node and node_cid:
        node_name = node.get("name") or node.get("mac") or node_cid
        return {
            "identifiers": {(DOMAIN, f"mesh_{node_cid}")},
            "name": f"Mesh - {node_name}",
            "manufacturer": "Keenetic",
            "model": node.get("model") or "Extender",
            "sw_version": node.get("firmware"),
            "via_device": (DOMAIN, entry_id),
        }
    
    # Fallback к главному устройству
    return get_main_device_info(title, entry_id)


def get_mesh_usb_device_info(
    title: str,
    entry_id: str,
    mesh_node_name: str,
    mesh_cid: Optional[str] = None,
) -> Dict[str, Any]:
    """Device info для USB на Mesh-ноде."""
    if mesh_cid:
        return {
            "identifiers": {(DOMAIN, f"mesh_{mesh_cid}")},
            "name": f"Mesh - {mesh_node_name}",
            "manufacturer": "Keenetic",
            "via_device": (DOMAIN, entry_id),
        }
    
    return get_main_device_info(title, entry_id)