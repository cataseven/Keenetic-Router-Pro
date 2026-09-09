"""Utilities for Keenetic Router Pro integration."""
import inspect
import ipaddress
import math
from typing import Any, Dict, Optional

from homeassistant.helpers import device_registry as dr

from .const import DOMAIN


def format_host_for_url(host: Optional[str]) -> Optional[str]:
    """Return ``host`` ready for embedding in a URL, or ``None``.

    Bare IPv6 literals must be wrapped in brackets per RFC 3986 —
    otherwise the colons parse as a port separator and HA's device
    registry rejects the ``configuration_url`` with "port can't be
    converted to integer", aborting entity setup (issue #62).

    Hostnames, IPv4 literals and already-bracketed hosts pass through
    unchanged. A host that contains colons but is *not* a parseable
    IPv6 literal can never form a valid URL authority, so ``None`` is
    returned — callers must then omit the URL entirely rather than
    crash the platform. Zone ids (``fe80::1%eth0``) are dropped from
    the URL form: RFC 6874 requires ``%25`` encoding that common URL
    parsers reject anyway, and a zone id is meaningless outside the
    router's own link.
    """
    if not host:
        return None
    candidate = str(host).strip()
    if not candidate:
        return None
    if candidate.startswith("["):
        return candidate
    if ":" not in candidate:
        return candidate
    addr = candidate.split("%", 1)[0]
    try:
        if ipaddress.ip_address(addr).version == 6:
            return f"[{addr}]"
    except ValueError:
        pass
    return None


# Issue #69. HA 2026.9 replaced DeviceInfo["via_device"] (an identifier
# tuple) with DeviceInfo["via_device_id"] (a device registry id string).
# The old key still works but logs "calls `device_registry.
# async_get_or_create` with a deprecated `via_device` parameter" and
# stops working in HA 2027.8.0.
#
# Older cores do NOT accept via_device_id: entity_platform splats the
# DeviceInfo dict straight into async_get_or_create, so an unknown
# keyword raises TypeError and the device is never created. Feature
# detection beats parsing __version__ because it survives backports.
try:
    _SUPPORTS_VIA_DEVICE_ID: bool = "via_device_id" in inspect.signature(
        dr.DeviceRegistry.async_get_or_create
    ).parameters
except (AttributeError, TypeError, ValueError):  # pragma: no cover
    _SUPPORTS_VIA_DEVICE_ID = False


def _via_device_kwargs(
    entry_id: str,
    via_device_id: Optional[str],
) -> Dict[str, Any]:
    """Return the DeviceInfo key that links a sub-device to the router.

    Passing both keys at once raises HomeAssistantError on modern
    cores, so exactly one of them is emitted. When the router's device
    id isn't known yet the key is omitted entirely rather than set to
    ``None``: an absent key leaves an already-stored link untouched,
    while ``None`` would clear it.
    """
    if _SUPPORTS_VIA_DEVICE_ID:
        return {"via_device_id": via_device_id} if via_device_id else {}
    return {"via_device": (DOMAIN, entry_id)}


def safe_float(value: Any) -> Optional[float]:
    """Convert ``value`` to a finite float, or return ``None``.

    Router firmware can occasionally emit ``NaN`` (division-by-zero in
    some sysstat exporter) or ``inf`` (overflow in a malformed
    counter) for what should be a normal numeric field. If those
    values reach a sensor declared as ``SensorStateClass.MEASUREMENT``
    they permanently corrupt HA's long-term-statistics table for that
    entity — the recorder treats NaN as a real sample and propagates
    it forward, breaking every dashboard graph that depends on the
    affected sensor.

    Returning ``None`` for any non-finite or non-coercible input lets
    affected sensors fall back to "unavailable" for that tick instead,
    which the recorder skips entirely.
    """
    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(f):
        return None
    return f


def safe_int(value: Any) -> Optional[int]:
    """Convert ``value`` to int, rejecting NaN/inf and conversion errors.

    Same rationale as ``safe_float``. Used by integer sensors (uptime,
    byte counters, packet counts) where the recorder is just as
    vulnerable to nonsense values.
    """
    f = safe_float(value)
    if f is None:
        return None
    return int(f)


def clamp_percent(value: Any) -> Optional[float]:
    """Convert to float and clamp to [0.0, 100.0].

    Transient firmware payloads where ``memfree`` briefly exceeds
    ``memtotal`` produce negative memory-usage percentages that look
    like ``-1.7%`` on the dashboard and break LTS aggregations.
    Clamping at the edges normalises those transients without losing
    the genuinely-out-of-range NaN/inf signal — those still return
    ``None``.
    """
    f = safe_float(value)
    if f is None:
        return None
    return max(0.0, min(100.0, f))


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
        safe_host = format_host_for_url(host)
        configuration_url = f"{scheme}://{safe_host}" if safe_host else None

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
    fqdn: str = None,
    via_device_id: Optional[str] = None,
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
            safe_ip = format_host_for_url(node_ip)
            configuration_url = f"{scheme}://{safe_ip}" if safe_ip else None

        return {
            "identifiers": {(DOMAIN, f"mesh_{node_cid}")},
            "name": node_name,
            "manufacturer": "Keenetic",
            "model": node.get("model") or "Extender",
            "sw_version": node.get("firmware"),
            **_via_device_kwargs(entry_id, via_device_id),
            "configuration_url": configuration_url,
        }

    # Fallback: attach to the router device without redefining it.
    # Returning a full main-device dict here would push model
    # "Controller" and a null firmware / configuration_url into the
    # registry, overwriting the real values — entity_platform splats
    # whatever device_info returns straight into async_get_or_create.
    return {"identifiers": {(DOMAIN, entry_id)}}


def get_wan_device_info(
    title: str,
    entry_id: str,
    wan_id: str,
    description: Optional[str] = None,
    iface_type: Optional[str] = None,
    role_label: Optional[str] = None,
    via_device_id: Optional[str] = None,
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
        **_via_device_kwargs(entry_id, via_device_id),
    }


def get_crypto_map_device_info(
    title: str,
    entry_id: str,
    cmap_name: str,
    remote_peer: Optional[str] = None,
    via_device_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Device info for a single site-to-site IPsec `crypto map` tunnel.

    Each configured tunnel appears in HA as its own sub-device under
    the main router, so the user can see one card per tunnel with all
    its sensors grouped (state, IKE state, RX/TX, throughput, enable
    switch, ...).

    The HA device identifier is keyed on the crypto map name, which
    is stable for the lifetime of the tunnel. Renaming the tunnel in
    the router web UI will orphan the old HA device and create a new
    one — there is no truly stable id for a crypto map entry, so this
    is an accepted tradeoff.
    """
    name_parts = [cmap_name]
    if remote_peer:
        name_parts.append(f"→ {remote_peer}")
    device_name = " ".join(name_parts)

    return {
        "identifiers": {(DOMAIN, f"{entry_id}_cmap_{cmap_name}")},
        "name": f"{title} — IPsec {device_name}",
        "manufacturer": "Keenetic",
        "model": "IPsec site-to-site tunnel",
        **_via_device_kwargs(entry_id, via_device_id),
    }


def get_client_device_info(
    entry_id: str,
    mac: str,
    label: str,
    client: Optional[Dict[str, Any]] = None,
    initial_ip: Optional[str] = None,
    via_device_id: Optional[str] = None,
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

    safe_ip = format_host_for_url(ip_address)
    return {
        "identifiers": {(DOMAIN, f"client_{mac.replace(':', '_')}")},
        "name": device_name,
        "manufacturer": manufacturer,
        "model": model,
        **_via_device_kwargs(entry_id, via_device_id),
        "configuration_url": f"http://{safe_ip}" if safe_ip else None,
        "connections": {("mac", mac.upper())},
    }
