from typing import Dict

from .const import DOMAIN

def device_info(
        title: str, 
        entry_id: int, 
        node: Dict = None, 
        node_cid = None):
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
    return {
        "identifiers": {(DOMAIN, f"controller_{entry_id}")},
        "name": f"Controller - {title}",
        "manufacturer": "Keenetic",
        "model": node.get("model") or "Controller",
        "sw_version": node.get("firmware"),
    }