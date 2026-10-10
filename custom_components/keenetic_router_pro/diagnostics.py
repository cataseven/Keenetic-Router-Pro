"""Diagnostics support for Keenetic Router Pro.

Home Assistant exposes a "Download diagnostics" button on every config
entry. The resulting JSON file is something users routinely attach to
GitHub issues, so it MUST NOT contain credentials, session cookies,
MAC addresses, SSIDs, pre-shared keys, NDW2 challenge headers, or any
other piece of router state that would let a reader compromise the
device or trivially identify the operator.

The redaction strategy is three-layered:

1. ``async_redact_data`` from Home Assistant walks the payload and
   replaces any value whose key matches the ``TO_REDACT`` set with
   ``**REDACTED**``. This handles the common case where the secret
   lives in a *value* (e.g. ``"password": "hunter2"``).

2. ``_strip_mac_keyed_indexes`` strips entire dict bodies for
   coordinator indexes whose **keys** are MAC addresses. HA's redactor
   only scrubs values, so MAC-keyed indexes need their own pass or
   the MACs leak through the keys themselves.

3. ``_mask_wifi_passwords`` masks the cached Wi-Fi PSKs, which sit
   under keys that no ``TO_REDACT`` entry can match.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .const import (
    DOMAIN,
    DATA_CLIENT,
    DATA_COORDINATOR,
    DATA_PING_COORDINATOR,
)


# Keys whose values must NEVER appear in a diagnostics dump.
# Matching is EXACT and case-sensitive — HA's redactor does a plain
# ``key in to_redact`` with no lower-casing — so a key that merely
# contains a sensitive word ("wifi_passwords") is NOT covered by its
# entry here ("password"). Such containers need their own pass below.
TO_REDACT: set[str] = {
    # Credentials / session
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_HOST,
    "password",
    "username",
    "login",
    "host",
    "token",
    "cookie",
    "set-cookie",
    "authorization",
    "x-ndm-challenge",
    "x-ndm-realm",
    # Auth handshake material (NDW2 / NDW4 / 5.2 access tokens). None of
    # it is in the payload today; listed so a future change that stores
    # handshake state on the coordinator can't leak it by accident.
    "www-authenticate",
    "x-ndm-data",
    "x-ndma-tkn",
    "challenge",
    "session_id",
    "session_cookie",
    "nonce",
    "salt",
    "proof",
    "signature",
    # Network identifiers
    "ip",
    "ip_address",
    "ipv4",
    "ipv6",
    "mac",
    "mac_address",
    "bssid",
    "ssid",
    # Keenetic payloads carry IPs under these keys too — including the
    # public WAN address ("address" on the uplink interface).
    "address",
    "gateway",
    "remote",
    "remote_peer",
    "local_endpoint",
    "remote_endpoint",
    "remote-endpoint-address",
    "local-endpoint-address",
    "ac-mac",
    # Wi-Fi PSKs / keys
    "psk",
    "passphrase",
    "pre_shared_key",
    "key",
    "secret",
    # Hardware identifiers — combined with model + firmware these
    # uniquely identify the operator's device.
    "serial",
    "serial_number",
    "hw_id",
    "hwid",
    "device_id",
    "uuid",
    # NDNS / DDNS hostnames are user-chosen and effectively a public
    # identifier of the operator.
    "domain",
    "fqdn",
}


# Coordinator indexes whose keys are MAC addresses or MAC-derived
# identifiers (mesh CIDs can fall back to MAC on firmwares without a
# separate CID). HA's ``async_redact_data`` only scrubs values, not
# keys — without this dedicated pass the MACs would leak through dict
# keys even after redaction. We replace the dict body with a row count
# so the diagnostics dump still tells a developer "yes there were N
# entries here" without exposing what they were.
_MAC_KEYED_INDEXES = (
    "host_policies",
    "traffic_shapes",
)


def _strip_mac_keyed_indexes(data: Any) -> Any:
    """Return a copy of coordinator data with MAC-keyed dicts collapsed."""
    if not isinstance(data, dict):
        return data
    stripped = dict(data)
    for key in _MAC_KEYED_INDEXES:
        if key in stripped and isinstance(stripped[key], dict):
            stripped[key] = {"<redacted-mac-keys>": len(stripped[key])}
    return stripped


def _mask_wifi_passwords(data: Any) -> Any:
    """Return a copy of coordinator data with Wi-Fi PSKs masked.

    ``wifi_passwords`` maps interface id -> PSK. Neither that key nor
    the interface ids match anything in ``TO_REDACT`` (matching is
    exact), so without this pass every network's password went into the
    dump in plain text. Non-empty values become ``**REDACTED**``; the ""
    not-found sentinel is kept, which still shows a developer which APs
    had a key — the one thing QR-code bug reports need.
    """
    if not isinstance(data, dict):
        return data
    passwords = data.get("wifi_passwords")
    if not isinstance(passwords, dict):
        return data
    masked = dict(data)
    masked["wifi_passwords"] = {
        iface: ("**REDACTED**" if pw else "") for iface, pw in passwords.items()
    }
    return masked


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return redacted diagnostics for a Keenetic config entry.

    Pulls the live coordinator data + a sanitized snapshot of the
    config entry, runs the whole payload through HA's redactor, and
    returns the result. Keys in ``TO_REDACT`` become ``**REDACTED**``;
    MAC-keyed indexes are replaced with row counts upstream of that.
    """
    entry_data = hass.data.get(DOMAIN, {}).get(entry.entry_id, {}) or {}
    coordinator = entry_data.get(DATA_COORDINATOR)
    client = entry_data.get(DATA_CLIENT)
    ping_coordinator = entry_data.get(DATA_PING_COORDINATOR)

    coordinator_data: Any = None
    if coordinator is not None:
        coordinator_data = _mask_wifi_passwords(
            _strip_mac_keyed_indexes(getattr(coordinator, "data", None))
        )

    ping_data: Any = None
    if ping_coordinator is not None:
        # Ping coordinator data is a dict {mac: bool} — also MAC-keyed.
        raw_ping = getattr(ping_coordinator, "data", None)
        if isinstance(raw_ping, dict):
            ping_data = {"<redacted-mac-keys>": len(raw_ping)}

    payload: dict[str, Any] = {
        "entry": {
            "title": entry.title,
            "version": entry.version,
            "domain": entry.domain,
            "source": entry.source,
            "data": dict(entry.data),
            "options": dict(entry.options),
        },
        "client": {
            # KeeneticClient.__repr__ already redacts username/password.
            # We pass it through async_redact_data anyway as defense in
            # depth in case __repr__ is ever weakened in a future PR.
            "repr": repr(client) if client is not None else None,
        },
        "coordinator_data": coordinator_data,
        "ping_coordinator_data": ping_data,
    }

    return async_redact_data(payload, TO_REDACT)
