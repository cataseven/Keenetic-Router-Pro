"""Low-level async API client for Keenetic Router Pro integration (Basic Auth to /rci)."""

from __future__ import annotations

from typing import Any, Optional, Dict, List
from homeassistant.exceptions import HomeAssistantError

import aiohttp
import async_timeout
import asyncio
import base64
import hashlib
import ipaddress
import logging
import re

from .const import DOMAIN
from .utils import safe_int

_LOGGER = logging.getLogger(f"custom_components.{DOMAIN}.api")

RCI_ROOT = "/rci"

# Strict allow-list for any value that is interpolated into a
# Keenetic `/rci/parse` CLI command (interface names, MAC addresses,
# crypto-map names, mesh CIDs, policy IDs, ...). Rejects anything that
# could break out of the single CLI token the caller intended:
# whitespace, quotes, backslash, shell metas, control characters, and
# Keenetic's own `\r\n` command separator. Accepted characters cover
# every legitimate token shape on this firmware family:
#   * interface ids — "GigabitEthernet0/Vlan35", "WifiMaster1/AccessPoint0"
#   * MACs         — "aa:bb:cc:dd:ee:ff"
#   * IPv4/IPv6    — "192.0.2.1", "2001:db8::1"
#   * policy names — "Policy0", user-defined "Smart Home" (no spaces -> rename)
#   * crypto maps  — "TEST", "SITE-TO-SITE_HQ"
_CLI_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:/\-]+$")


def _data_usage_to_gb(value: Any, unit: str) -> Optional[float]:
    """Convert a traffic-counter amount to GB.

    Keenetic surfaces ``value``/``limit``/``threshold``/``remaining``
    as strings in whatever unit the user picked for that interface's
    counter (GB on most home setups, but the router accepts KB / MB /
    TB too). Sensors should always speak GB so HA's long-term
    statistics and any user-side automations have a single yardstick.
    Returns None on any parse failure rather than 0 — "unknown" should
    look different from "zero usage" in the UI.
    """
    try:
        val = float(str(value))
    except (TypeError, ValueError):
        return None
    if val < 0:
        return None
    unit_u = (unit or "GB").strip().upper()
    if unit_u == "GB":
        return val
    if unit_u == "MB":
        return val / 1024.0
    if unit_u == "KB":
        return val / (1024.0 * 1024.0)
    if unit_u in ("B", "BYTES"):
        return val / (1024.0 * 1024.0 * 1024.0)
    if unit_u == "TB":
        return val * 1024.0
    return val  # unknown unit — pass through, better than dropping the value


def _validate_cli_arg(value: str, label: str) -> str:
    """Return a safe Keenetic CLI token or raise on command-injection input.

    Every value that is going to be interpolated into an `/rci/parse`
    command must go through this gate. The router executes the parsed
    command as a CLI line, so an unvalidated value containing a space
    + a second command would run that command too. The allow-list above
    matches the legitimate token shapes Keenetic uses and rejects
    everything else.
    """
    if value is None:
        raise KeeneticApiError(f"Empty {label}")
    raw = str(value)
    candidate = raw.strip()
    if not candidate:
        raise KeeneticApiError(f"Empty {label}")
    # A value that needed stripping had a leading/trailing whitespace
    # character — refuse it rather than silently accepting the stripped
    # form, because that is exactly the shape command-injection input
    # likes to take (" foo ; bad cmd ").
    if candidate != raw:
        raise KeeneticApiError(f"Unsafe {label}")
    if not _CLI_TOKEN_RE.fullmatch(candidate):
        raise KeeneticApiError(f"Unsafe {label}")
    return candidate


def _is_endpoint_missing(err: BaseException) -> bool:
    """Return True if ``err`` looks like a "router doesn't have this endpoint".

    Two shapes we treat as equivalent to "feature absent":

    1. HTTP 404 from ``_request`` — wrapped in a ``KeeneticApiError``
       whose message contains ``"HTTP error 404"``.
    2. The router's RCI "not found" string returned by ``/rci/parse``
       or some show endpoints when the feature module isn't loaded.

    Anything else (5xx, timeouts, malformed JSON, transient connection
    errors) is a real fault, not a missing feature, and must NOT
    suppress future calls.
    """
    msg = str(err).lower()
    if "404" in msg:
        return True
    if "not found" in msg:
        return True
    return False


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
        use_challenge_auth: bool = False,
    ) -> None:
        self._host = host
        self._username = username
        self._password = password
        self._port = port
        self._ssl = ssl
        self._request_timeout = request_timeout
        self._use_challenge_auth = use_challenge_auth

        scheme = "https" if ssl else "http"
        # Bracket IPv6 literals so the URL is valid (#57). A bare
        # ``http://2a00:...:4ee2:100/`` is ambiguous — yarl/aiohttp cannot
        # tell the address colons from the port separator. Hostnames, IPv4,
        # and already-bracketed values pass through unchanged.
        host_part = host
        try:
            if isinstance(host, str) and isinstance(
                ipaddress.ip_address(host), ipaddress.IPv6Address
            ):
                host_part = f"[{host}]"
        except ValueError:
            # Not a bare IP literal (hostname / KeenDNS / already bracketed).
            pass
        self._base = f"{scheme}://{host_part}:{port}"

        self._session: Optional[aiohttp.ClientSession] = None
        self._auth_header: Optional[Dict[str, str]] = None
        self._authenticated: bool = False

        # Capability caches. Each attr starts as ``None`` (unknown), is
        # flipped to ``False`` the first time the corresponding endpoint
        # returns 404 / "not found" (and subsequent ticks skip the call
        # entirely so the router stops logging "not found: <feature>"
        # every poll), and stays ``True`` once the endpoint has been
        # observed to work at least once.
        self._mws_member_supported: bool | None = None
        self._crypto_map_supported: bool | None = None
        self._ping_check_supported: bool | None = None
        self._ndns_supported: bool | None = None
        # Sprint 4 capabilities: DNS proxy diagnostics + IPsec VICI log
        # parsing. Same None/False/True pattern as the rest — once we
        # learn the endpoint isn't on this firmware, stop calling it.
        self._dns_proxy_supported: bool | None = None
        self._ipsec_diagnostics_supported: bool | None = None

        # Sprint 6 (issue #49): per-interface "doesn't exist on this
        # router" cache. Populated when `show/interface/<id>` returns
        # 404 — used to short-circuit subsequent calls into
        # ``async_get_wifi_password`` for non-existent APs (e.g.
        # WifiMaster0/AccessPoint1 on a router without Guest Wi-Fi).
        # Without this cache, every coordinator tick fires 3-4 router
        # log errors per non-existent AP — pavlozelinskyi observed
        # 3,900 errors in 1.5 hours from this single bug.
        self._missing_interface_paths: set[str] = set()

        # Serialise auth refreshes. The coordinator's stage-1 fan-out
        # fires 13 RCI calls in parallel; if the session expires between
        # ticks, every one of those calls hits ``_ensure_auth`` at the
        # same time, each schedules its own challenge handshake, and
        # they race to overwrite ``_auth_header`` and ``_authenticated``.
        # The losing handshakes leave the client in an inconsistent
        # state and the next RCI call observes a spurious 401. The lock
        # forces refresh to happen exactly once per "expired session"
        # event regardless of caller concurrency.
        self._auth_lock: asyncio.Lock = asyncio.Lock()


    def __repr__(self) -> str:
        """Redacted repr — never expose username/password in logs/tracebacks.

        Without this override, a stray ``_LOGGER.debug("client=%s", client)``
        or a traceback containing the client instance would leak both
        credentials into ``home-assistant.log``. Host/port/SSL stay
        visible because those are useful for troubleshooting and not
        secret.
        """
        return (
            f"KeeneticClient(host={self._host!r}, port={self._port}, "
            f"ssl={self._ssl}, username='<redacted>', password='<redacted>', "
            f"challenge_auth={self._use_challenge_auth})"
        )

    __str__ = __repr__


    async def async_start(self, session: aiohttp.ClientSession) -> None:
        """Attach an aiohttp session and authenticate."""
        self._session = session
        if self._use_challenge_auth:
            await self._async_authenticate_challenge()
        else:
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

    async def _async_authenticate_challenge(self) -> None:
        """Perform NDW2 challenge-response auth used by newer Keenetic models (e.g. Hero).

        Handshake:
          1. GET /auth  → 401 with X-NDM-Challenge + X-NDM-Realm headers + Set-Cookie
          2. Compute:
               ha1      = md5(username:realm:password)
               response = sha256(challenge + ha1)
          3. POST /auth  with JSON {login, password: response}  and the session cookie
          4. 200 → authenticated; subsequent requests use only the session cookie.
        """
        if self._session is None:
            raise KeeneticAuthError("ClientSession is not set")

        auth_url = f"{self._base}/auth"

        # --- Step 1: GET /auth to obtain challenge & session cookie ---
        _LOGGER.debug("NDW2 challenge auth: GET %s", auth_url)
        try:
            async with async_timeout.timeout(self._request_timeout):
                get_resp = await self._session.get(auth_url, allow_redirects=False)
        except aiohttp.ClientError as err:
            raise KeeneticAuthError(f"Challenge GET failed: {err}") from err

        _LOGGER.debug(
            "NDW2 challenge GET response: status=%s headers=%s",
            get_resp.status,
            dict(get_resp.headers),
        )

        if get_resp.status not in (200, 401):
            text = await get_resp.text()
            raise KeeneticAuthError(
                f"Unexpected status during challenge GET ({get_resp.status}): {text}"
            )

        challenge = get_resp.headers.get("X-NDM-Challenge")
        realm = get_resp.headers.get("X-NDM-Realm", "")

        if not challenge:
            raise KeeneticAuthError(
                "Router did not return X-NDM-Challenge header. "
                "This model may not support Challenge Auth — "
                "try disabling 'Challenge Auth' and use Basic Auth instead."
            )

        _LOGGER.debug("NDW2 challenge=%s realm=%s", challenge, realm)

        # Extract session cookie from Set-Cookie header
        session_cookie: str | None = None
        # Extract session cookie manually — HA's shared CookieJar(unsafe=False)
        # silently ignores cookies from bare IP addresses.
        raw_cookie = get_resp.headers.get("Set-Cookie", "")
        if raw_cookie:
            cookie_kv = raw_cookie.split(";")[0].strip()
            if "=" in cookie_kv:
                session_cookie = cookie_kv

        _LOGGER.debug("NDW2 session cookie: %s", session_cookie)

        # --- Step 2: Compute NDW2 hashes ---
        # ha1      = md5(username:realm:password)   [hex digest]
        # response = sha256(challenge + ha1)         [hex digest]
        ha1 = hashlib.md5(
            f"{self._username}:{realm}:{self._password}".encode()
        ).hexdigest()
        response_hash = hashlib.sha256((challenge + ha1).encode()).hexdigest()

        _LOGGER.debug(
            "NDW2 hash: ha1(md5)=%s response(sha256)=%s", ha1, response_hash
        )

        # --- Step 3: POST /auth with credentials + explicit Cookie header ---
        payload = {"login": self._username, "password": response_hash}
        post_headers: Dict[str, str] = {}
        if session_cookie:
            post_headers["Cookie"] = session_cookie

        _LOGGER.debug("NDW2 challenge: POST %s payload_login=%s", auth_url, self._username)

        try:
            async with async_timeout.timeout(self._request_timeout):
                post_resp = await self._session.post(
                    auth_url,
                    json=payload,
                    headers=post_headers,
                )
        except aiohttp.ClientError as err:
            raise KeeneticAuthError(f"Challenge POST failed: {err}") from err

        post_text = await post_resp.text()
        _LOGGER.debug(
            "NDW2 challenge POST response: status=%s body=%s",
            post_resp.status,
            post_text[:200],
        )

        if post_resp.status == 401:
            raise KeeneticAuthError(
                f"Challenge auth rejected — wrong credentials? (body={post_text!r})"
            )
        if post_resp.status not in (200, 204):
            raise KeeneticAuthError(
                f"Challenge auth failed (status={post_resp.status}, body={post_text!r})"
            )

        # Store cookie in _auth_header so every subsequent RCI request includes it.
        self._auth_header = {"Cookie": session_cookie} if session_cookie else {}
        self._authenticated = True

        _LOGGER.debug(
            "Authenticated to Keenetic router at %s:%s (NDW2 challenge OK)",
            self._host,
            self._port,
        )

    async def _ensure_auth(self) -> None:
        """Ensure we are authenticated before making an RCI call.

        Double-checked locking: the fast path (already authenticated)
        avoids touching the lock at all, so the common case doesn't
        pay any synchronisation cost. The slow path acquires the lock,
        re-checks the flag (in case another concurrent caller already
        re-authenticated while we were waiting), and only then runs
        the actual handshake.

        Without the lock, the coordinator's 13-way parallel stage-1
        fetch races each other through ``_async_authenticate`` /
        ``_async_authenticate_challenge`` and they overwrite each
        other's ``_auth_header``, leaving the client in an
        inconsistent state and producing spurious 401s.
        """
        if self._authenticated:
            return
        async with self._auth_lock:
            if self._authenticated:
                return
            if self._use_challenge_auth:
                await self._async_authenticate_challenge()
            else:
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
        """Raw /rci/show/interface çıktısını evrensel listeye çevir.

        Dict anahtarları (ör. "ISP", "GigabitEthernet0") interface'in adıdır.
        Kaybolmaması için, içeride "id" yoksa anahtar adı enjekte edilir.
        """
        if isinstance(raw, dict):
            # {"GigabitEthernet0": {...}, "WifiMaster0/AccessPoint0": {...}}
            result = []
            for key, val in raw.items():
                if not isinstance(val, dict):
                    continue
                if "id" not in val:
                    val = {**val, "id": key}
                result.append(val)
            return result
        if isinstance(raw, list):
            # [ {...}, {...} ]
            return [v for v in raw if isinstance(v, dict)]
        return []

    async def async_ping_ip(self, ip_address: str, timeout: float = 2.0) -> bool:
        """Ping an IP address using the router's ping functionality.

        Returns True if the host is reachable, False otherwise.
        """
        try:

            safe_ip = _validate_cli_arg(ip_address, "ip address")
            result = await self._rci_parse(f"ip ping {safe_ip} count 1")

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

    async def async_get_current_version_info(self) -> Dict[str, Any]:
        """Return version info"""
        data = await self._rci_get("show/version")
        return data or {}

    async def async_get_available_version_info(self) -> Dict[str, Any]:
        """Return version info"""
        data = await self._rci_get("components/check-update")
        return data or {}

    async def async_get_port_info(self, interfaces: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
        """Return physical port information for the main router.

        Ports are found in show/interface as top-level entries with type "Port".
        Example keys: "0", "1", "2", "3", "4" with label and link status.

        Also checks GigabitEthernet*.port nested dicts as fallback.
        """
        if interfaces is None:
            interfaces = await self.async_get_interfaces()

        if not interfaces or not isinstance(interfaces, dict):
            return []

        ports: List[Dict[str, Any]] = []
        seen_labels: set = set()

        # Method 1: Top-level Port entries (keys like "0", "1", "2", "3", "4")
        for iface_id, iface in interfaces.items():
            if not isinstance(iface, dict):
                continue
            if iface.get("type") != "Port":
                continue

            label = iface.get("label") or iface.get("interface-name") or iface_id
            if label in seen_labels:
                continue
            seen_labels.add(label)

            entry: Dict[str, Any] = {
                "label": label,
                "appearance": iface.get("type"),
                "link": iface.get("link", "unknown"),
            }
            if iface.get("link") == "up":
                entry["speed"] = iface.get("speed")
                entry["duplex"] = iface.get("duplex")
            ports.append(entry)

        if ports:
            # Sort by label for consistent ordering
            ports.sort(key=lambda p: str(p.get("label", "")))
            _LOGGER.debug("Found %d main router ports from top-level Port entries", len(ports))
            return ports

        # Method 2: Nested port dicts inside GigabitEthernet interfaces
        for iface_id, iface in interfaces.items():
            if not isinstance(iface, dict):
                continue
            if iface.get("type") != "GigabitEthernet":
                continue

            port_data = iface.get("port")
            if not port_data or not isinstance(port_data, dict):
                continue

            # port can be a single dict (GigabitEthernet1) or dict of dicts (GigabitEthernet0)
            if "label" in port_data:
                # Single port dict
                label = port_data.get("label") or port_data.get("interface-name")
                if label and label not in seen_labels:
                    seen_labels.add(label)
                    entry = {
                        "label": label,
                        "appearance": port_data.get("type"),
                        "link": port_data.get("link", "unknown"),
                    }
                    if port_data.get("link") == "up":
                        entry["speed"] = port_data.get("speed")
                        entry["duplex"] = port_data.get("duplex")
                    ports.append(entry)
            else:
                # Dict of port dicts (keyed by port number)
                for port_key, port_val in port_data.items():
                    if not isinstance(port_val, dict):
                        continue
                    label = port_val.get("label") or port_val.get("interface-name") or port_key
                    if label in seen_labels:
                        continue
                    seen_labels.add(label)
                    entry = {
                        "label": label,
                        "appearance": port_val.get("type"),
                        "link": port_val.get("link", "unknown"),
                    }
                    if port_val.get("link") == "up":
                        entry["speed"] = port_val.get("speed")
                        entry["duplex"] = port_val.get("duplex")
                    ports.append(entry)

        if ports:
            ports.sort(key=lambda p: str(p.get("label", "")))
            _LOGGER.debug("Found %d main router ports from nested GigabitEthernet port data", len(ports))
        else:
            _LOGGER.warning("No physical ports found for main router")

        return ports

    async def async_get_interfaces(self) -> Dict[str, Any]:
        """Return raw interfaces dictionary from /rci/show/interface."""
        data = await self._rci_get("show/interface")
        return data or {}

    async def async_get_wifi_password(self, interface_id: str) -> str | None:
        """Get WiFi password (PSK) for a specific interface.

        Tries multiple API paths since different firmware versions
        store the PSK in different locations.
        """
        # Issue #49 short-circuit: a previous tick learned this
        # interface doesn't exist on the router (typically
        # WifiMaster0/AccessPoint1 on routers without Guest Wi-Fi).
        # Hitting it again would generate 3-4 router-log errors per
        # tick for no benefit. Cache lives until HA reload — if the
        # user enables Guest Wi-Fi at runtime they need to reload the
        # integration to pick it up.
        if interface_id in self._missing_interface_paths:
            return None

        def _extract_psk(data: Any) -> str | None:
            """Extract PSK from various possible data structures."""
            if not isinstance(data, dict):
                return None

            # Path: authentication.wpa-psk.psk
            auth = data.get("authentication", {})
            if isinstance(auth, dict):
                wpa_psk = auth.get("wpa-psk", {})
                if isinstance(wpa_psk, dict) and wpa_psk.get("psk"):
                    return str(wpa_psk["psk"])

            # Path: security-level.wpa.psk
            sec = data.get("security-level", {})
            if isinstance(sec, dict):
                wpa = sec.get("wpa", {})
                if isinstance(wpa, dict) and wpa.get("psk"):
                    return str(wpa["psk"])

            # Path: wpa.psk
            wpa = data.get("wpa", {})
            if isinstance(wpa, dict) and wpa.get("psk"):
                return str(wpa["psk"])

            # Direct key
            if data.get("key"):
                return str(data["key"])

            return None

        # Track endpoint-missing (404 / "not found") errors across the
        # methods that actually hit the router over the network. We
        # used to (Sprint 6) cache + return None right inside Method 1's
        # exception handler — that turned a single-endpoint 404 into a
        # permanent "no password" verdict for the interface, which is
        # exactly the regression that produced QR codes encoded as
        # ``T:nopass`` after v1.8.0 shipped on firmwares where
        # ``show/interface/<id>`` 404s for an AccessPoint that
        # ``interface/<id>`` / CLI parse happily expose. The cache is
        # now populated only at the END of the function, after every
        # method has been exhausted — and only if every network method
        # we attempted reported the endpoint as missing. That preserves
        # the issue #49 spam fix for *genuinely* non-existent
        # interfaces while letting real APs fall through to the next
        # method.
        network_methods_attempted = 0
        network_methods_missing = 0

        # Method 1: GET show/interface/{id} - interface status with details
        try:
            data = await self._rci_get(f"show/interface/{interface_id}")
            network_methods_attempted += 1
            _LOGGER.debug("WiFi password Method 1 (show/interface/%s) response keys: %s",
                         interface_id, list(data.keys()) if isinstance(data, dict) else type(data))
            psk = _extract_psk(data)
            if psk:
                _LOGGER.debug("WiFi password found via Method 1 for %s", interface_id)
                return psk
        except KeeneticApiError as err:
            network_methods_attempted += 1
            if _is_endpoint_missing(err):
                network_methods_missing += 1
                _LOGGER.debug(
                    "WiFi password Method 1 endpoint-missing for %s "
                    "— falling through to Methods 2-5",
                    interface_id,
                )
            else:
                _LOGGER.debug("WiFi password Method 1 failed for %s: %s", interface_id, err)
        except Exception as err:  # noqa: BLE001
            network_methods_attempted += 1
            _LOGGER.debug("WiFi password Method 1 failed for %s: %s", interface_id, err)

        # Method 2: GET interface/{id} - running configuration
        try:
            data = await self._rci_get(f"interface/{interface_id}")
            network_methods_attempted += 1
            _LOGGER.debug("WiFi password Method 2 (interface/%s) response keys: %s",
                         interface_id, list(data.keys()) if isinstance(data, dict) else type(data))
            psk = _extract_psk(data)
            if psk:
                _LOGGER.debug("WiFi password found via Method 2 for %s", interface_id)
                return psk
        except KeeneticApiError as err:
            network_methods_attempted += 1
            if _is_endpoint_missing(err):
                network_methods_missing += 1
            _LOGGER.debug("WiFi password Method 2 failed for %s: %s", interface_id, err)
        except Exception as err:
            network_methods_attempted += 1
            _LOGGER.debug("WiFi password Method 2 failed for %s: %s", interface_id, err)

        # Method 3: POST show/interface with nested query
        try:
            data = await self._rci_post("show/interface", {interface_id: {}})
            network_methods_attempted += 1
            _LOGGER.debug("WiFi password Method 3 (POST show/interface) response keys: %s",
                         list(data.keys()) if isinstance(data, dict) else type(data))
            # Two response shapes are seen across firmware versions:
            #   1. ``{"<interface_id>": {…fields…}}``  (nested per-interface)
            #   2. ``{…auth/wpa fields at root…}``     (flat)
            # A *phantom* interface (no Guest Wi-Fi configured but the
            # AP slot still listed) produces a third shape: ``{}`` or
            # the queried key absent entirely. The POST endpoint
            # itself returns 200 OK in that case, so our ``except``
            # branch never fires and ``network_methods_missing`` never
            # ticks — which is exactly the bug that left issue #49's
            # AccessPoint1 spam unfixed in v1.8.1. We now treat
            # "endpoint OK but nothing about this interface" as
            # semantically equivalent to a 404 for cache purposes.
            psk: str | None = None
            interface_data_present = False
            if isinstance(data, dict) and data:
                nested = data.get(interface_id)
                if nested:
                    interface_data_present = True
                    if isinstance(nested, dict):
                        psk = _extract_psk(nested)
                elif any(
                    k in data
                    for k in ("authentication", "security-level", "wpa", "key")
                ):
                    # Flat form — PSK fields directly on the root.
                    interface_data_present = True
                    psk = _extract_psk(data)
            if psk:
                _LOGGER.debug("WiFi password found via Method 3 for %s", interface_id)
                return psk
            if not interface_data_present:
                network_methods_missing += 1
                _LOGGER.debug(
                    "WiFi password Method 3 returned no data for %s "
                    "— counting as endpoint-missing",
                    interface_id,
                )
        except KeeneticApiError as err:
            network_methods_attempted += 1
            if _is_endpoint_missing(err):
                network_methods_missing += 1
            _LOGGER.debug("WiFi password Method 3 failed for %s: %s", interface_id, err)
        except Exception as err:
            network_methods_attempted += 1
            _LOGGER.debug("WiFi password Method 3 failed for %s: %s", interface_id, err)

        # Method 4: Look in the already-fetched full interfaces dict
        try:
            interfaces = await self.async_get_interfaces()
            if interface_id in interfaces:
                iface_data = interfaces[interface_id]
                _LOGGER.debug("WiFi password Method 4 (full interfaces[%s]) keys: %s",
                             interface_id, list(iface_data.keys()) if isinstance(iface_data, dict) else type(iface_data))
                psk = _extract_psk(iface_data)
                if psk:
                    _LOGGER.debug("WiFi password found via Method 4 for %s", interface_id)
                    return psk

            # Also try matching by SSID across all interfaces
            for iface_id, iface in interfaces.items():
                if not isinstance(iface, dict):
                    continue
                psk = _extract_psk(iface)
                if psk:
                    _LOGGER.debug("WiFi password found via SSID scan in interface %s", iface_id)
                    return psk
        except Exception as err:
            _LOGGER.debug("WiFi password Method 4 failed for %s: %s", interface_id, err)

        # Method 5: CLI parse
        try:
            safe_iface = _validate_cli_arg(interface_id, "interface id")
            result = await self._rci_parse(f"more interface {safe_iface}")
            network_methods_attempted += 1
            _LOGGER.debug("WiFi password Method 5 (CLI) response: %s",
                         str(result)[:500] if result else "None")
            # The Keenetic CLI never raises HTTP 404 for unknown
            # interfaces — it returns a 200 OK body with an "Argument
            # parse error" string (sometimes "command not found",
            # sometimes "unknown interface"). Treat any of those as
            # "this interface doesn't exist" so the cache populator
            # picks up phantom AccessPoints. Without this gate, Method
            # 5 quietly inflates ``attempted`` without inflating
            # ``missing`` and the final check ``missing == attempted``
            # is always one short. (Same root cause as the Method 3
            # fix immediately above — different symptom.)
            method5_missing = False
            if not result:
                method5_missing = True
            else:
                result_str = str(result).lower()
                if any(
                    needle in result_str
                    for needle in (
                        "argument parse error",
                        "command not found",
                        "unknown interface",
                        "not found",
                        "no such",
                    )
                ):
                    method5_missing = True
                else:
                    for line in str(result).splitlines():
                        line_lower = line.strip().lower()
                        if "psk" in line_lower or "key" in line_lower:
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                candidate = parts[-1].strip('"').strip("'")
                                if len(candidate) >= 8:
                                    return candidate
            if method5_missing:
                network_methods_missing += 1
                _LOGGER.debug(
                    "WiFi password Method 5: CLI rejected interface %s "
                    "— counting as endpoint-missing",
                    interface_id,
                )
        except KeeneticApiError as err:
            network_methods_attempted += 1
            if _is_endpoint_missing(err):
                network_methods_missing += 1
            _LOGGER.debug("WiFi password Method 5 failed for %s: %s", interface_id, err)
        except Exception as err:
            network_methods_attempted += 1
            _LOGGER.debug("WiFi password Method 5 failed for %s: %s", interface_id, err)

        # Post-exhaustion cache populate (issue #49 spam fix, properly
        # gated). If every network endpoint we tried reported the
        # interface as missing, this AP genuinely doesn't exist on the
        # router — typically a phantom WifiMaster0/AccessPoint1 on a
        # firmware that surfaces the slot in the interface list but
        # has no actual configuration for it. Cache so subsequent
        # ticks short-circuit at the top instead of generating 4
        # router-log errors per tick.
        #
        # We require at least 2 methods to have actually reported
        # missing — a single network blip during one method shouldn't
        # be enough to blacklist a real interface, and the in-memory
        # Method 4 is intentionally excluded from the count.
        if (
            network_methods_attempted >= 2
            and network_methods_missing == network_methods_attempted
        ):
            _LOGGER.debug(
                "Interface %s reported missing by all %d network methods "
                "— caching to suppress per-tick log spam",
                interface_id, network_methods_missing,
            )
            self._missing_interface_paths.add(interface_id)

        _LOGGER.warning(
            "Could not retrieve WiFi password for interface %s. "
            "QR code will be generated without password. "
            "Check debug logs for details.",
            interface_id,
        )
        return None

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

            # Issue #49 follow-up: skip interfaces that the function-level
            # password-fetch cache (``_missing_interface_paths``) already
            # confirmed don't exist on this router. Without this filter,
            # Sprint 8's orphan-AP logic (issue #45) can give a phantom
            # AccessPoint slot the SSID of its real same-group partner —
            # which then surfaces as an extra QR entity that has no PSK,
            # because the password lookup short-circuits on the cache.
            # Filtering at enumeration time keeps the cache's truth from
            # leaking back into the UI as a confusing duplicate network.
            if raw_id in self._missing_interface_paths:
                continue

            clone = dict(item)
            clone["__id"] = raw_id
            ap_items.append(clone)

        # ===================================================================
        # Issue #45 grouping fix.
        #
        # The old code used ``group_key = group or ssid or base_id``, which
        # collapsed any two APs sharing a Keenetic bridge ``group`` into a
        # single logical network — even when their SSIDs were deliberately
        # different. Reporter's setup:
        #   * "Chapay"    on WifiMaster0/AccessPoint0 (2.4 GHz)
        #   * "Chapay_5G" on WifiMaster1/AccessPoint0 (5 GHz)
        # Both APs share the LAN bridge, so they had the same ``group``.
        # The old loop set ``g["ssid"] = ssid`` on every iteration — last
        # write wins — so the 5 GHz SSID overwrote the 2.4 GHz one and the
        # 2.4 GHz network ended up labelled "Wi-Fi Chapay_5G 2.4 GHz".
        #
        # New approach: group by ``(group, ssid)`` when an SSID is present.
        # Two APs with different SSIDs no longer merge regardless of bridge
        # membership. Disabled APs (no SSID in the payload) get attached
        # afterwards to a partner with the same ``group`` only if the
        # partnership is unambiguous (exactly one logical network in that
        # bridge); otherwise the orphan AP stands alone with a fallback
        # display name. This preserves the original "disabled 2.4 GHz
        # partner inherits the real SSID from the enabled 5 GHz partner"
        # behaviour for genuine dual-band same-SSID setups.
        # ===================================================================

        # Pass 1: APs that broadcast a real SSID get keyed by (group, ssid).
        groups: Dict[tuple, Dict[str, Any]] = {}
        orphan_aps: List[Dict[str, Any]] = []  # APs with empty SSID
        for item in ap_items:
            raw_id = item["__id"]
            ssid = (item.get("ssid") or "").strip()
            group = str(item.get("group") or "").strip()
            base_id = raw_id.split("/")[0]

            if not ssid:
                # Defer — Pass 2 decides whether to attach to a
                # partner or keep as standalone.
                orphan_aps.append(item)
                continue

            # When a group is missing we fall back to the SSID itself
            # (so SSID-only routers still work) and finally the base
            # interface id (so a router that exposes APs with neither
            # field still produces *some* entry per AP).
            group_key: tuple = (group or "", ssid) if (group or ssid) else ("", base_id)

            g = groups.setdefault(
                group_key,
                {
                    "ssid": ssid,
                    "group": group,
                    "aps": [],
                },
            )
            # All APs reaching this branch share the same SSID already,
            # so assignment is idempotent — no last-write-wins risk.
            g["ssid"] = ssid
            g["aps"].append(item)

        # Pass 2: place orphan (no-SSID) APs.
        # Build an index from group -> list of logical networks that
        # already live in that group.
        group_to_networks: Dict[str, List[Dict[str, Any]]] = {}
        for (grp, _ssid), g in groups.items():
            if grp:
                group_to_networks.setdefault(grp, []).append(g)

        for item in orphan_aps:
            raw_id = item["__id"]
            group = str(item.get("group") or "").strip()
            base_id = raw_id.split("/")[0]
            networks_in_group = group_to_networks.get(group, [])

            if group and len(networks_in_group) == 1:
                # Exactly one logical network in this bridge — the
                # orphan is unambiguously its disabled partner band.
                # Attach so the SSID is inherited correctly. This is
                # the dual-band-same-SSID disabled-partner case the
                # original code was trying to handle.
                networks_in_group[0]["aps"].append(item)
            else:
                # Either no group or multiple logical networks share
                # the group — partnership is ambiguous. Keep this AP
                # as its own entry with a synthetic key; bridge label
                # / base id will be used for display in the next loop.
                synthetic_key = ("__orphan__", raw_id)
                groups[synthetic_key] = {
                    "ssid": "",
                    "group": group,
                    "aps": [item],
                }

        # Second pass: any group that still has no real SSID (e.g. every
        # AP in the group is disabled and the firmware stripped the field
        # from all of them) falls back to the bridge label or group id,
        # so the entry at least has *some* logical name for display.
        for g in groups.values():
            if g["ssid"]:
                continue
            grp = g["group"]
            if grp and grp in bridge_labels:
                g["ssid"] = bridge_labels[grp]
            elif grp:
                g["ssid"] = grp

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
        safe = _validate_cli_arg(interface_name, "interface name")
        cmd = f"interface {safe} {'up' if enabled else 'down'}"
        _LOGGER.debug("Set Wi-Fi %s enabled=%s via: %s", interface_name, enabled, cmd)
        await self._rci_parse(cmd)

    async def async_set_wireguard_enabled(self, interface_name: str, enabled: bool) -> None:
        """Enable or disable a WireGuard interface via RCI parse.

        Kept for backwards compatibility; delegates to the generic
        async_set_interface_enabled which works for any interface type
        (WireGuard, OpenVPN, SSTP, IPsec, ...).
        """
        await self.async_set_interface_enabled(interface_name, enabled)

    async def async_set_interface_enabled(self, interface_name: str, enabled: bool) -> None:
        """Enable or disable any interface via RCI 'interface X up/down'."""
        safe = _validate_cli_arg(interface_name, "interface name")
        cmd = f"interface {safe} {'up' if enabled else 'down'}"
        _LOGGER.debug(
            "Set interface %s enabled=%s via: %s",
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
            "sstp",
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

        Durum mantığı:
          - "connected"  → interface up VE IP mevcut
          - "link_up"    → interface up AMA IP yok (ISP sorunu vb.)
          - "down"       → interface bulunamadı veya down
        """
        if interfaces is None:
            interfaces = await self.async_get_interfaces()
        iface_list = self._normalize_interfaces(interfaces)

        # ---------- yardımcı: interface'den IP çıkar ----------
        def _extract_ip(iface: Dict[str, Any]) -> str | None:
            """Try every known Keenetic address field/format."""
            # 1) global-address (Keenetic 4.x+)
            gaddr = iface.get("global-address")
            if isinstance(gaddr, list) and gaddr:
                first = gaddr[0]
                if isinstance(first, dict):
                    ip = first.get("address") or first.get("ip")
                    if ip:
                        return str(ip).split("/")[0]
                elif isinstance(first, str):
                    return first.split("/")[0]

            # 2) address alanı
            address = iface.get("address")
            if isinstance(address, list) and address:
                first = address[0]
                if isinstance(first, dict):
                    ip = first.get("address") or first.get("ip")
                    if ip:
                        return str(ip).split("/")[0]
                elif isinstance(first, str):
                    return first.split("/")[0]
            elif isinstance(address, str) and address:
                return address.split("/")[0]

            # 3) doğrudan ip / ipv4 alanı
            for key in ("ip", "ipv4", "ip-address"):
                val = iface.get(key)
                if val and isinstance(val, str):
                    return val.split("/")[0]

            return None

        # ---------- yardımcı: sonuç oluştur ----------
        def _build_result(
            iface: Dict[str, Any], wan_type: str
        ) -> Dict[str, Any]:
            wan_ip = _extract_ip(iface)
            link_state = str(iface.get("state") or "").lower()
            status = "connected" if (link_state == "up" and wan_ip) else (
                "link_up" if link_state == "up" else "down"
            )
            return {
                "status": status,
                "ip": wan_ip,
                "interface": iface.get("id") or iface.get("interface-name"),
                "uptime": iface.get("uptime"),
                "gateway": (
                    iface.get("gateway")
                    or iface.get("remote")
                    or iface.get("default-gateway")
                ),
                "type": wan_type,
                "link": link_state,
            }

        # ---------- yardımcı: WAN keyword eşleşmesi ----------
        WAN_KEYWORDS = ("wan", "internet", "isp", "broadband")

        def _is_wan_iface(iface: Dict[str, Any]) -> bool:
            """Interface'in WAN olup olmadığını birden fazla ipucuyla belirle."""
            # security-level: public → Keenetic'te WAN demek
            sec = str(iface.get("security-level") or "").lower()
            if sec == "public":
                return True
            # role: inet
            role = str(iface.get("role") or "").lower()
            if role in ("inet", "internet", "wan"):
                return True
            # İsim tabanlı arama
            name_fields = [
                iface.get("name"),
                iface.get("ifname"),
                iface.get("id"),
                iface.get("interface-name"),
                iface.get("description"),
                iface.get("type"),
            ]
            name_joined = " ".join(str(v) for v in name_fields if v).lower()
            return any(k in name_joined for k in WAN_KEYWORDS)

        # ========== 1) PPPoE (öncelikli) ==========
        for iface in iface_list:
            itype = str(iface.get("type") or "").lower()
            state = str(iface.get("state") or "").lower()
            if itype == "pppoe" and state == "up":
                return _build_result(iface, "pppoe")

        # ========== 2) WAN interface (state == "up") ==========
        for iface in iface_list:
            state = str(iface.get("state") or "").lower()
            if state == "up" and _is_wan_iface(iface):
                return _build_result(iface, "ethernet")

        # ========== 3) WAN interface (state != "up" — link_up/down) ==========
        for iface in iface_list:
            if _is_wan_iface(iface):
                return _build_result(iface, "ethernet")

        return {"status": "down", "ip": None, "link": "down"}

    async def async_get_wan_interfaces(
        self, interfaces: Dict[str, Any] | None = None
    ) -> List[Dict[str, Any]]:
        """Return per-uplink info for every configured WAN interface.

        Enumerates *all* uplink-capable interfaces Keenetic knows about —
        not just the currently active one — so Home Assistant can expose
        a full picture of the multi-WAN / failover configuration.

        WAN detection logic (derived from real show/interface output):
          - `global: true` — interface has a routable, "public-facing" role
          - `priority` is set — interface participates in Keenetic's
            uplink priority ordering (this is what puts an interface into
            the "Connection priorities" list in the web UI)
          - `role` contains "inet" — explicit uplink tag
          Any interface matching (`global=true` AND `priority` is set),
          OR with `role` containing "inet", is treated as a WAN.

          Interfaces that are merely carriers for a PPPoE/VLAN (e.g. the
          raw GigabitEthernet1 below PPPoE0) are *not* WANs — they have
          `global: false` and no `priority`, so they fail the filter
          naturally. They show up as `via` / `underlying` on the WAN that
          rides on top of them.

        Each entry in the returned list contains:
            id                 interface id (PPPoE0, Wireguard0, ...)
            description        human-readable description from the router
                               UI ("Telekom", "Zurich"), falls back to id
            interface_name     the "interface-name" field (e.g. "ISP")
            type               interface type (PPPoE / Wireguard / ...)
            link_state         "up" / "down"
            enabled            bool — True when the interface is configured
                               up (summary.layer.conf != "disabled")
            global             bool — has a global (public) role
            defaultgw          bool — currently the default gateway
            priority           int — Keenetic uplink priority (higher wins)
            role               list[str] — e.g. ["inet"]
            security_level     "public" / "private" / "protected"
            ip                 current public IP, if any
            mask               subnet mask, if any
            uptime             seconds since the session came up
            underlying         id of the physical/logical interface this
                               session rides on (PPPoE `via`), if any
            remote             remote peer address (PPPoE/tunnel)
            mac                L2 address if applicable
            internet_access    bool — best-effort ping-check / reachability
                               heuristic (see _derive_internet_access)
            summary_layers     nested summary.layer dict (conf/link/ipv4/...)
            raw                the untouched interface dict, for consumers
                               that want a field we didn't pull out
        """
        if interfaces is None:
            interfaces = await self.async_get_interfaces()
        iface_list = self._normalize_interfaces(interfaces)

        def _is_wan(iface: Dict[str, Any]) -> bool:
            # Explicit uplink role is the strongest signal.
            role = iface.get("role")
            if isinstance(role, list) and any(
                str(r).lower() in ("inet", "internet", "wan") for r in role
            ):
                return True
            if isinstance(role, str) and role.lower() in ("inet", "internet", "wan"):
                return True

            # Otherwise: global + priority is how Keenetic marks an
            # interface as a ranked uplink. Both conditions must hold —
            # `global: true` alone catches LAN bridges in some configs,
            # and `priority` alone catches non-uplink routing tweaks.
            is_global = bool(iface.get("global"))
            has_priority = iface.get("priority") is not None
            return is_global and has_priority

        def _extract_ip(iface: Dict[str, Any]) -> str | None:
            # PPPoE/static: flat "address" string. Ethernet WANs in some
            # firmware versions use global-address/address lists.
            addr = iface.get("address")
            if isinstance(addr, str) and addr:
                return addr.split("/")[0]
            gaddr = iface.get("global-address")
            if isinstance(gaddr, list) and gaddr:
                first = gaddr[0]
                if isinstance(first, dict):
                    v = first.get("address") or first.get("ip")
                    if v:
                        return str(v).split("/")[0]
                elif isinstance(first, str):
                    return first.split("/")[0]
            if isinstance(addr, list) and addr:
                first = addr[0]
                if isinstance(first, dict):
                    v = first.get("address") or first.get("ip")
                    if v:
                        return str(v).split("/")[0]
                elif isinstance(first, str):
                    return first.split("/")[0]
            return None

        def _derive_enabled(iface: Dict[str, Any]) -> bool:
            # summary.layer.conf == "disabled" means the interface is
            # toggled off in the config — matches the UI toggle exactly.
            summary = iface.get("summary") or {}
            layer = summary.get("layer") or {}
            conf = str(layer.get("conf") or "").lower()
            if conf == "disabled":
                return False
            if conf == "running":
                return True
            # Fallback: if we don't have a summary, assume enabled unless
            # state says otherwise.
            return True

        def _derive_internet_access(iface: Dict[str, Any]) -> bool | None:
            """Best-effort ping-check / reachability indicator.

            Keenetic's raw show/interface output on this firmware does
            *not* expose the ping-check result as a distinct field — the
            red "NO INTERNET ACCESS (PING CHECK)" badge in the web UI is
            computed client-side from a different RCI call that's not
            uniformly available across firmware versions.

            As a pragmatic substitute we use:
                up  = state=="up" AND global AND has routable IP
                     AND summary.layer.ipv4 in {"running"}
                down = state != "up" OR global is false OR no IP
                unknown (None) = state up but no public IP yet (pending)

            This matches the user-visible "this WAN is actually usable"
            meaning for the common case (PPPoE up with IP, WG tunnel up
            with handshake) without false-positiving on carrier
            interfaces or half-initialised uplinks.
            """
            state = str(iface.get("state") or "").lower()
            if state != "up":
                return False
            if not iface.get("global"):
                return False
            ip = _extract_ip(iface)
            if not ip:
                summary = iface.get("summary") or {}
                layer = summary.get("layer") or {}
                if str(layer.get("ipv4") or "").lower() == "pending":
                    return None
                return False
            # Extra guard: PPPoE exposes `fail` when the last session
            # attempt failed.
            fail = str(iface.get("fail") or "").lower()
            if fail in ("yes", "true"):
                return False
            return True

        wans: List[Dict[str, Any]] = []
        for iface in iface_list:
            if not _is_wan(iface):
                continue
            iface_id = iface.get("id") or iface.get("interface-name")
            if not iface_id:
                continue

            role = iface.get("role")
            if isinstance(role, str):
                role_list = [role]
            elif isinstance(role, list):
                role_list = [str(r) for r in role]
            else:
                role_list = []

            wans.append({
                "id": iface_id,
                "description": iface.get("description") or iface.get("interface-name") or iface_id,
                "interface_name": iface.get("interface-name"),
                "type": iface.get("type"),
                "link_state": str(iface.get("state") or "down").lower(),
                "enabled": _derive_enabled(iface),
                "global": bool(iface.get("global")),
                "defaultgw": bool(iface.get("defaultgw")),
                "priority": iface.get("priority"),
                "role": role_list,
                "security_level": iface.get("security-level"),
                "ip": _extract_ip(iface),
                "mask": iface.get("mask"),
                "uptime": iface.get("uptime"),
                "underlying": iface.get("via"),
                "remote": iface.get("remote"),
                "mac": iface.get("mac"),
                "internet_access": _derive_internet_access(iface),
                "summary_layers": (iface.get("summary") or {}).get("layer") or {},
                "raw": iface,
            })

        return wans

    async def async_get_ping_check_status(self) -> Dict[str, Any]:
        """Return the router's ping-check results per interface.

        This is the authoritative "is the internet actually reachable
        through this WAN" signal — the same data that drives the red
        "NO INTERNET ACCESS (PING CHECK)" badge in the Keenetic web UI
        and that the router itself uses to decide when to fail over to
        a backup uplink.

        Endpoint: rci/show/ping-check
        Example response:
            {
              "pingcheck": [
                {
                  "profile": "default",
                  "host": ["captive.keenetic.net"],
                  "port": 80,
                  "update-interval": 30,
                  "max-fails": 3,
                  "mode": "icmp",
                  "interface": {
                    "PPPoE0": {
                      "successcount": 7,
                      "failcount": 0,
                      "status": "pass",
                      "ipcache": [
                        {"host": "captive.keenetic.net",
                         "addresses": ["135.181.129.158", "..."]}
                      ]
                    }
                  }
                }
              ]
            }

        Returns a flat dict keyed by interface id:
            {
              "PPPoE0": {
                "status": "pass",                 # "pass" | "fail"
                "success_count": 7,
                "fail_count": 0,
                "profile": "default",             # winning profile name
                "check_hosts": ["captive.keenetic.net"],
                "check_addresses": ["135.181.129.158", ...],
                "check_port": 80,
                "check_mode": "icmp",
                "update_interval": 30,
                "max_fails": 3,
                "all_profiles": [                 # every profile touching
                  {"profile": "...", "status": "...", ...}   # this iface
                ],
              }
            }

        A router may have multiple profiles bound to the same interface.

        IMPORTANT: profiles named `_WEBADMIN_<InterfaceId>` are NOT
        transient — current Keenetic firmware persists user-enabled
        Ping Check configurations under that name when the user toggles
        "Check the Availability of the Internet (Ping Check)" in the
        web UI. They have real `update-interval`, `max-fails`, real
        check hosts and live counters, and they ARE the authoritative
        ping-check signal for that WAN.

        We instead identify *truly* transient profiles by their target
        address: one-off connection tests target IANA documentation /
        TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
        Those are the only profiles we ignore.

        When multiple authoritative profiles report on the same interface,
        the aggregate status is "fail" if any profile is failing (matches
        how Keenetic itself treats the WAN as unusable for routing).
        """
        # Capability gate: once we learn this firmware doesn't expose
        # show/ping-check (older models, custom builds, IPsec-only
        # routers), stop hitting it on every coordinator tick — the
        # router otherwise spams its own log with "not found: ping-check"
        # at ~6/minute on the default poll interval.
        if self._ping_check_supported is False:
            return {}

        try:
            data = await self._rci_get("show/ping-check") or {}
        except KeeneticApiError as err:
            if _is_endpoint_missing(err):
                _LOGGER.debug(
                    "show/ping-check not supported on this router, "
                    "caching as absent"
                )
                self._ping_check_supported = False
                return {}
            raise

        # First successful response — pin capability so we never re-test.
        self._ping_check_supported = True

        raw_profiles = data.get("pingcheck") or []
        if not isinstance(raw_profiles, list):
            return {}

        # Collect per-interface observations from every profile that
        # actually has results (profile without `interface` block is
        # just a definition with nothing attached yet).
        observations: Dict[str, List[Dict[str, Any]]] = {}
        for profile_entry in raw_profiles:
            if not isinstance(profile_entry, dict):
                continue
            iface_map = profile_entry.get("interface")
            if not isinstance(iface_map, dict) or not iface_map:
                continue

            profile_name = str(profile_entry.get("profile") or "")
            host = profile_entry.get("host")
            if isinstance(host, str):
                hosts = [host]
            elif isinstance(host, list):
                hosts = [str(h) for h in host if h]
            else:
                hosts = []

            for iface_id, iface_result in iface_map.items():
                if not isinstance(iface_result, dict):
                    continue
                ipcache = iface_result.get("ipcache") or []
                addresses: List[str] = []
                cache_hosts: List[str] = []
                if isinstance(ipcache, list):
                    for entry in ipcache:
                        if not isinstance(entry, dict):
                            continue
                        h = entry.get("host")
                        if h:
                            cache_hosts.append(str(h))
                        addrs = entry.get("addresses") or []
                        if isinstance(addrs, list):
                            addresses.extend(str(a) for a in addrs if a)

                # Prefer ipcache hosts over profile-level host list when
                # both exist (ipcache reflects what the router actually
                # resolved and probed).
                effective_hosts = cache_hosts or hosts

                observation = {
                    "profile": profile_name,
                    "status": str(iface_result.get("status") or "").lower() or None,
                    "success_count": iface_result.get("successcount"),
                    "fail_count": iface_result.get("failcount"),
                    "check_hosts": effective_hosts,
                    "check_addresses": addresses,
                    "check_port": profile_entry.get("port"),
                    "check_mode": profile_entry.get("mode"),
                    "update_interval": profile_entry.get("update-interval"),
                    "max_fails": profile_entry.get("max-fails"),
                }
                observations.setdefault(iface_id, []).append(observation)

        # Per interface, pick "authoritative" profiles and aggregate.
        #
        # We only ignore profiles whose check targets fall entirely
        # inside IANA TEST-NET / documentation ranges, because those
        # are the one-off connection tests the web UI fires when the
        # user clicks "test connection" — they intentionally target
        # unroutable addresses and would otherwise produce permanent
        # false "fail" results.
        #
        # We do NOT filter by profile name. In particular,
        # `_WEBADMIN_<InterfaceId>` profiles are persistent, real,
        # user-enabled Ping Check configurations created from the
        # router's web UI — they are the authoritative ping-check
        # signal for that WAN and MUST be honoured.
        def _is_test_net_only(observation: Dict[str, Any]) -> bool:
            addrs = observation.get("check_addresses") or []
            hosts = observation.get("check_hosts") or []
            candidates = [str(x) for x in (list(addrs) + list(hosts)) if x]
            if not candidates:
                return False
            test_net_prefixes = ("192.0.2.", "198.51.100.", "203.0.113.")
            return all(c.startswith(test_net_prefixes) for c in candidates)

        result: Dict[str, Any] = {}
        for iface_id, obs_list in observations.items():
            real = [o for o in obs_list if not _is_test_net_only(o)]

            if not real:
                # Only TEST-NET probe profiles exist — don't trust them,
                # fall back to the link+IP heuristic downstream.
                result[iface_id] = {
                    "status": None,
                    "passing": None,
                    "profile": None,
                    "success_count": None,
                    "fail_count": None,
                    "check_hosts": [],
                    "check_addresses": [],
                    "check_port": None,
                    "check_mode": None,
                    "update_interval": None,
                    "max_fails": None,
                    "all_profiles": obs_list,
                    "ignored_profiles": [o.get("profile") for o in obs_list],
                }
                continue

            effective = real

            # Aggregate status: any "fail" wins, all "pass" -> "pass",
            # otherwise whatever the last-seen status is (typically a
            # profile in "pending"/"checking" state that's newly added).
            statuses = [o.get("status") for o in effective if o.get("status")]
            if not statuses:
                agg_status: str | None = None
                agg_bool: bool | None = None
            elif any(s == "fail" for s in statuses):
                agg_status = "fail"
                agg_bool = False
            elif all(s == "pass" for s in statuses):
                agg_status = "pass"
                agg_bool = True
            else:
                # Mixed or unknown state — surface as None so the
                # sensor goes "unavailable" rather than lying.
                agg_status = statuses[-1]
                agg_bool = None

            # The "winning" profile is the first fail (if any), else the
            # first pass — gives the most useful single-profile summary
            # for attribute display.
            primary: Dict[str, Any] | None = None
            for o in effective:
                if o.get("status") == "fail":
                    primary = o
                    break
            if primary is None:
                for o in effective:
                    if o.get("status") == "pass":
                        primary = o
                        break
            if primary is None and effective:
                primary = effective[0]

            flat: Dict[str, Any] = {
                "status": agg_status,
                "passing": agg_bool,
                "profile": (primary or {}).get("profile"),
                "success_count": (primary or {}).get("success_count"),
                "fail_count": (primary or {}).get("fail_count"),
                "check_hosts": (primary or {}).get("check_hosts") or [],
                "check_addresses": (primary or {}).get("check_addresses") or [],
                "check_port": (primary or {}).get("check_port"),
                "check_mode": (primary or {}).get("check_mode"),
                "update_interval": (primary or {}).get("update_interval"),
                "max_fails": (primary or {}).get("max_fails"),
                "all_profiles": obs_list,
                "ignored_profiles": [
                    o.get("profile") for o in obs_list if o not in effective
                ],
            }
            result[iface_id] = flat

        return result

    async def async_get_crypto_maps(self) -> Dict[str, Dict[str, Any]]:
        """Return site-to-site IPsec tunnels (`crypto map` entries).

        Endpoint: rci/show/crypto/map

        Site-to-site IPsec tunnels do NOT appear as virtual interfaces
        in /rci/show/interface, so they need their own data path and
        their own entity model — they can't piggyback on the existing
        per-WAN / per-VPN-client plumbing that other VPN types use.

        The router response looks like (tunnel that never came up):
            {
              "crypto_map": {
                "TEST": {
                  "config": {
                    "remote_peer": "192.0.2.1",
                    "enabled": "yes",              # NOTE: string, not bool
                    "crypto_ipsec_profile_name": "TEST",
                    "mode": "tunnel"
                  },
                  "status": {
                    "primary_peer": true,
                    "initiator": true,
                    "ike_state": "UNDEFINED",
                    "state": "UNDEFINED",
                    "via": "PPPoE0",
                    "local-endpoint-address": "78.188.13.104",
                    "remote-endpoint-address": "192.0.2.1"
                  }
                }
              }
            }

        A fully established tunnel additionally has `status.phase1`
        (dict) and `status.phase2_sa_list.phase2_sa` (list of SA dicts
        with in_bytes / out_bytes counters). We treat those as optional
        because the router only populates them once SA negotiation has
        actually happened.

        We normalise to:
            {
              "<name>": {
                "name": "TEST",
                "enabled": True,                   # config.enabled == "yes"
                "remote_peer": "192.0.2.1",
                "mode": "tunnel",
                "ipsec_profile_name": "TEST",
                "state": "UNDEFINED",              # status.state
                "ike_state": "UNDEFINED",          # status.phase1.ike_state
                                                   #   or status.ike_state
                "connected": False,                # state == PHASE2_ESTABLISHED
                "via": "PPPoE0" or None,
                "local_endpoint": "78.188.13.104" or None,
                "remote_endpoint": "192.0.2.1" or None,
                "rx_bytes": 1506697,               # sum across phase2 SAs
                "tx_bytes": 129642,                # sum across phase2 SAs
                "rx_packets": 2950,
                "tx_packets": 2360,
                "phase1": {...} or None,           # raw, for v2 sensors
                "phase2_sa_list": [...] or [],     # raw, normalised to list
                "raw_status": {...},               # raw status for diag
                "raw_config": {...},
              }
            }
        """
        # Capability gate: routers without the IPsec component never
        # expose show/crypto/map and answer 404 every call. Cache the
        # answer the first time we learn it.
        if self._crypto_map_supported is False:
            return {}

        try:
            data = await self._rci_get("show/crypto/map") or {}
        except KeeneticApiError as err:
            if _is_endpoint_missing(err):
                _LOGGER.debug(
                    "show/crypto/map not supported on this router, "
                    "caching as absent"
                )
                self._crypto_map_supported = False
                return {}
            # Real transport / auth / 5xx error — re-raise so the
            # coordinator's per-tick warning aggregator sees it.
            _LOGGER.debug("show/crypto/map unavailable: %s", err)
            raise
        except asyncio.CancelledError:
            # Never swallow shutdown — HA reload depends on this
            # propagating up through the coordinator.
            raise
        except Exception as err:  # noqa: BLE001
            # Keep the original best-effort behaviour for truly weird
            # router responses (malformed JSON, etc.) so a single odd
            # firmware doesn't break the integration entirely.
            _LOGGER.debug("show/crypto/map unavailable: %s", err)
            return {}

        # First successful response — pin capability.
        self._crypto_map_supported = True

        raw_maps = data.get("crypto_map") or {}
        if not isinstance(raw_maps, dict):
            return {}

        def _clean_addr(v: Any) -> str | None:
            """Reject '0.0.0.0' / empty / None placeholders."""
            if v is None:
                return None
            s = str(v).strip()
            if not s or s == "0.0.0.0" or s == "::":
                return None
            return s

        def _clean_str(v: Any) -> str | None:
            if v is None:
                return None
            s = str(v).strip()
            return s or None

        def _to_int(v: Any) -> int:
            try:
                return int(v)
            except (TypeError, ValueError):
                return 0

        def _as_list(v: Any) -> List[Any]:
            """Keenetic sometimes collapses single-entry lists to a
            dict. Normalise to a real list so downstream code can
            always iterate."""
            if v is None:
                return []
            if isinstance(v, list):
                return v
            if isinstance(v, dict):
                return [v]
            return []

        result: Dict[str, Dict[str, Any]] = {}
        for name, entry in raw_maps.items():
            if not isinstance(entry, dict):
                continue

            config = entry.get("config") or {}
            status = entry.get("status") or {}
            if not isinstance(config, dict):
                config = {}
            if not isinstance(status, dict):
                status = {}

            # phase1 may live either under status.phase1 (when router
            # has negotiated) or — on some firmwares — the ike_state
            # field alone is promoted to status.ike_state with no
            # phase1 block. Handle both.
            phase1 = status.get("phase1")
            if not isinstance(phase1, dict):
                phase1 = None

            ike_state = None
            if phase1:
                ike_state = _clean_str(phase1.get("ike_state"))
            if not ike_state:
                ike_state = _clean_str(status.get("ike_state"))

            # phase2 SA list — present only when SAs have been set up.
            p2_wrapper = status.get("phase2_sa_list") or {}
            if not isinstance(p2_wrapper, dict):
                p2_wrapper = {}
            phase2_sa_list = _as_list(p2_wrapper.get("phase2_sa"))

            rx_bytes = 0
            tx_bytes = 0
            rx_packets = 0
            tx_packets = 0
            for sa in phase2_sa_list:
                if not isinstance(sa, dict):
                    continue
                rx_bytes += _to_int(sa.get("in_bytes"))
                tx_bytes += _to_int(sa.get("out_bytes"))
                rx_packets += _to_int(sa.get("in_packets"))
                tx_packets += _to_int(sa.get("out_packets"))

            state = _clean_str(status.get("state"))
            connected = state == "PHASE2_ESTABLISHED"

            result[name] = {
                "name": name,
                "enabled": str(config.get("enabled", "")).lower() == "yes",
                "remote_peer": _clean_str(config.get("remote_peer")),
                "mode": _clean_str(config.get("mode")),
                "ipsec_profile_name": _clean_str(
                    config.get("crypto_ipsec_profile_name")
                ),
                "state": state,
                "ike_state": ike_state,
                "connected": connected,
                "via": _clean_str(status.get("via")),
                "local_endpoint": _clean_addr(
                    status.get("local-endpoint-address")
                ),
                "remote_endpoint": _clean_addr(
                    status.get("remote-endpoint-address")
                ),
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "rx_packets": rx_packets,
                "tx_packets": tx_packets,
                "phase1": phase1,
                "phase2_sa_list": phase2_sa_list,
                "raw_config": config,
                "raw_status": status,
            }

        return result

    async def async_set_crypto_map_enabled(
        self, name: str, enabled: bool
    ) -> None:
        """Enable or disable a site-to-site IPsec `crypto map` entry.

        Unlike VPN-client interfaces (which are toggled via
        `interface X up/down`), site-to-site tunnels live under the
        `crypto map <name>` configuration sub-mode. The CLI pattern is:

            crypto map <name>
              enable     (or: no enable)

        We send this as a single RCI parse call with an embedded
        newline. Changes are runtime-only until persisted, so we
        follow up with `system configuration save` so the toggle
        survives a reboot — matching the user's expectation that a
        Home Assistant switch toggle is permanent.
        """
        verb = "enable" if enabled else "no enable"
        safe_name = _validate_cli_arg(name, "crypto map name")
        cmd = f"crypto map {safe_name}\n{verb}"
        _LOGGER.debug(
            "Set crypto map %s enabled=%s via: %r", name, enabled, cmd
        )
        await self._rci_parse(cmd)
        # Persist so the change survives a reboot. Without this the
        # toggle is lost on the next router restart and the user sees
        # the switch "flip back" with no obvious reason.
        try:
            await self._rci_parse("system configuration save")
        except Exception as err:
            _LOGGER.warning(
                "crypto map %s toggled to enabled=%s but "
                "'system configuration save' failed: %s — change will "
                "be lost on reboot",
                name,
                enabled,
                err,
            )


    async def async_get_mesh_nodes(self) -> List[Dict[str, Any]]:
        """Get mesh/extender nodes status from mws/member endpoint.

        Bu endpoint tüm mesh üyelerini detaylı bilgileriyle döndürür.

        NOT:
        Bazı Keenetic modellerinde/firmware'lerinde Wi-Fi System (MWS) controller yoktur.
        Bu durumda show/mws/member çağrısı router loguna:
            Core::Scgi::ThreadPool: not found: "member" (http/rci)
        şeklinde spam basar.

        Çözüm:
        1) Önce client listesinde extender/repeater var mı bak.
           Yoksa MWS endpoint'ine hiç gitme.
        2) MWS endpoint'i "not found" ise desteklenmiyor diye cache'le, tekrar deneme.
        """
        nodes: List[Dict[str, Any]] = []

        # 1) Önce fallback ile "evde extender var mı?" tespit et
        try:
            fallback_nodes = await self._get_mesh_nodes_from_clients()
        except Exception:
            fallback_nodes = []

        # Extender yoksa MWS endpoint'ine hiç dokunma (log spam sıfır)
        if not fallback_nodes:
            return nodes

        # Daha önce "desteklemiyor" diye cache'lediysek tekrar deneme
        if self._mws_member_supported is False:
            return fallback_nodes

        try:
            data = await self._rci_get("show/mws/member")

            # Endpoint çalıştı
            self._mws_member_supported = True

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
                    and member.get("internet-available", False)
                )

                ports = member.get("port", [])
                normalized_ports = []
                for port in ports:
                    if isinstance(port, dict):
                        normalized_port = {
                            "label": port.get("label"),
                            "appearance": port.get("appearance"),
                            "link": port.get("link"),
                        }
                        if port.get("link") == "up":
                            normalized_port["speed"] = port.get("speed")
                            normalized_port["duplex"] = port.get("duplex")
                        normalized_ports.append(normalized_port)

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
                    "fqdn": member.get("fqdn"),
                    "port": normalized_ports,
                    "backhaul": member.get("backhaul"),
                })

        except Exception as err:
            # "not found" durumunda tekrar denemeyip cache'leyelim
            msg = str(err).lower()
            if ("not found" in msg) or ("404" in msg):
                self._mws_member_supported = False
                return fallback_nodes

            _LOGGER.debug("Error getting mesh nodes from mws/member: %s", err)
            return fallback_nodes

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

        safe_cid = _validate_cli_arg(cid, "mesh node cid")
        cmd = f"mws member {safe_cid} reboot"
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
            WAN_KEYWORDS = ("wan", "internet", "pppoe", "isp", "provider")

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
                    stats["total_rx"] = (
                        iface.get("rxbytes") or
                        iface.get("rx-bytes") or
                        iface.get("bytes-rx") or
                        iface.get("rx") or
                        0
                    )
                    stats["total_tx"] = (
                        iface.get("txbytes") or
                        iface.get("tx-bytes") or
                        iface.get("bytes-tx") or
                        iface.get("tx") or
                        0
                    )

                    rx_speed = (
                        iface.get("rx-speed") or
                        iface.get("rxspeed") or
                        iface.get("speed-rx") or
                        iface.get("rx_rate") or
                        0
                    )
                    tx_speed = (
                        iface.get("tx-speed") or
                        iface.get("txspeed") or
                        iface.get("speed-tx") or
                        iface.get("tx_rate") or
                        0
                    )

                    stats["download_speed"] = round(float(rx_speed) / 8 / 1024 / 1024, 2)
                    stats["upload_speed"] = round(float(tx_speed) / 8 / 1024 / 1024, 2)

                    _LOGGER.debug(
                        "Traffic stats for %s: rx=%s, tx=%s, rx_speed=%s, tx_speed=%s",
                        name_joined, stats["total_rx"], stats["total_tx"],
                        stats["download_speed"], stats["upload_speed"]
                    )
                    break

        except Exception as err:
            _LOGGER.debug("Error getting traffic stats: %s", err)

        return stats

    async def async_get_all_interface_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get traffic statistics for all interfaces.

        Returns dict mapping interface name to stats (rxbytes, txbytes, etc.)
        """
        interfaces = await self.async_get_interfaces()
        iface_list = self._normalize_interfaces(interfaces)

        all_stats: Dict[str, Dict[str, Any]] = {}

        for iface in iface_list:
            iface_name = iface.get("id") or iface.get("interface-name")
            if not iface_name:
                continue

            # Пропускаем внутренние интерфейсы (Bridge, Vlan, AccessPoint),
            # НО никогда не пропускаем uplink: VLAN-WAN — обычное дело
            # (провайдер раздаёт интернет через тегированный VLAN). См. #56.
            iface_type = iface.get("type", "").lower()
            role = iface.get("role")
            is_uplink = (
                (isinstance(role, list)
                 and any(str(r).lower() in ("inet", "internet", "wan") for r in role))
                or (isinstance(role, str) and role.lower() in ("inet", "internet", "wan"))
                or (bool(iface.get("global")) and iface.get("priority") is not None)
            )
            if iface_type in ("bridge", "vlan", "accesspoint") and not is_uplink:
                continue

            try:
                stats = await self.async_get_interface_stat(iface_name)
                if stats:
                    # Добавляем информацию об интерфейсе
                    stats["interface_name"] = iface_name
                    stats["interface_type"] = iface_type
                    stats["link"] = iface.get("link")
                    stats["state"] = iface.get("state")
                    all_stats[iface_name] = stats
            except Exception as err:
                _LOGGER.debug("Failed to get stats for %s: %s", iface_name, err)

        return all_stats

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
        elif isinstance(partitions, dict) and partitions:
            first = next(iter(partitions.values()))
            if isinstance(first, dict):
                part0 = first

        total = self._to_int((part0 or {}).get("total")) or self._to_int(media_info.get("size"))
        # Read free as raw value so None (missing) is distinct from 0 (actually empty).
        free_raw = (part0 or {}).get("free")
        free = self._to_int(free_raw) if free_raw is not None else None
        if total and free is not None:
            used = max(total - free, 0)
        else:
            used = self._to_int((part0 or {}).get("used"))

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
            "free": free if free is not None else 0,
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

            # Issue #48: a device is "connected" if EITHER the explicit
            # ``active`` flag is true OR the L2 ``link`` is up. Treating
            # these as mutually exclusive (elif) was wrong: cross-subnet
            # devices (e.g. ESP32 on a routed sub-LAN 192.168.3.0/24
            # while HA runs in 192.168.1.0/24) frequently come back with
            # ``active=false`` even though the L2 link is up and the
            # device is reachable to the router. They were being
            # counted as disconnected — Connected Devices sensor read
            # 3 when 5 were actually online. Either signal is sufficient.
            is_active = False
            if "active" in client:
                value = client.get("active")
                if isinstance(value, bool):
                    is_active = value
                elif isinstance(value, str):
                    is_active = value.lower() in ("true", "yes", "1", "up", "online")
                else:
                    is_active = bool(value)
            if not is_active and "link" in client:
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
        # Every CLI interpolation goes through `_validate_cli_arg` so a
        # crafted MAC or policy name (e.g. from a Keenetic web UI with
        # weakened input validation, or from corrupted config) cannot
        # smuggle in a second CLI command. We validate the normalized
        # MAC because that's what hits the command line.
        safe_mac = _validate_cli_arg(mac_clean, "client mac")

        if policy.lower() == "deny":
            cmd = f"ip hotspot host {safe_mac} deny"
            _LOGGER.debug("Blocking client %s", mac_clean)
            await self._rci_parse(cmd)
        elif policy.lower() in ("default", "permit", ""):

            cmd = f"no ip hotspot host {safe_mac} policy"
            _LOGGER.debug("Removing policy from client %s", mac_clean)
            await self._rci_parse(cmd)

            cmd = f"ip hotspot host {safe_mac} permit"
            await self._rci_parse(cmd)
        else:
            # Önce erişimi aç (deny durumundaysa permit'e çevir)
            cmd = f"ip hotspot host {safe_mac} permit"
            await self._rci_parse(cmd)

            safe_policy = _validate_cli_arg(policy, "policy id")
            cmd = f"ip hotspot host {safe_mac} policy {safe_policy}"
            _LOGGER.debug("Setting client %s policy to %s", mac_clean, policy)
            await self._rci_parse(cmd)

        await self._rci_parse("system configuration save")

    async def async_block_client(self, mac: str) -> None:
        """Block a client's internet access."""
        await self.async_set_client_policy(mac, "deny")

    async def async_unblock_client(self, mac: str) -> None:
        """Unblock a client's internet access."""
        await self.async_set_client_policy(mac, "default")

    async def async_get_traffic_shapes(self) -> Dict[str, int]:
        """Get per-host bandwidth limits (``ip traffic-shape`` config).

        Returns a mapping of normalised MAC (lowercase, colon-separated)
        to the configured rate in **kbit/s**. Hosts without a configured
        rate are absent from the dict — callers should treat absence as
        "unlimited" rather than zero.

        The endpoint shape we rely on (verified against firmware via
        the maintainer's router): ``GET /rci/ip/traffic-shape/host``
        returns a flat list of ``{mac, rate}`` objects. A small subset
        of older firmwares wrap it under a top-level ``host`` key
        (``GET /rci/ip/traffic-shape``), which we accept as a fallback.

        Routers without the ``traffic-shape`` component installed
        return 404 — we cache that on the first miss so subsequent
        ticks short-circuit, matching how other optional features
        (DNS proxy, IPsec VICI, ping-check) behave. Issue #42.
        """
        if getattr(self, "_traffic_shape_supported", True) is False:
            return {}

        def _parse(payload: Any) -> Dict[str, int]:
            # Accept both ``[{mac, rate}, ...]`` and ``{"host": [...]}``
            # plus the very-occasional ``{"host": {<mac>: {rate}}}``
            # variant some firmware betas use.
            entries: list = []
            if isinstance(payload, list):
                entries = payload
            elif isinstance(payload, dict):
                inner = payload.get("host", payload)
                if isinstance(inner, list):
                    entries = inner
                elif isinstance(inner, dict):
                    # mac-keyed dict form
                    entries = [
                        {"mac": k, **(v if isinstance(v, dict) else {})}
                        for k, v in inner.items()
                    ]
            out: Dict[str, int] = {}
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                mac = str(entry.get("mac") or "").lower().replace("-", ":")
                rate = entry.get("rate")
                # Only accept ints / numeric strings — anything else is
                # a parser surprise and we'd rather show "no limit" than
                # populate the slider with garbage.
                rate_int = safe_int(rate)
                if mac and isinstance(rate_int, int) and rate_int > 0:
                    out[mac] = rate_int
            return out

        # Primary endpoint first — fastest, most direct shape.
        try:
            data = await self._rci_get("ip/traffic-shape/host")
            return _parse(data)
        except KeeneticApiError as err:
            if _is_endpoint_missing(err):
                # Fall through to the alternate shape before deciding
                # the whole feature is unsupported.
                pass
            else:
                _LOGGER.debug("traffic-shape/host fetch error: %s", err)
                return {}
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("traffic-shape/host fetch error: %s", err)
            return {}

        # Alternate endpoint shape for some firmwares.
        try:
            data = await self._rci_get("ip/traffic-shape")
            return _parse(data)
        except KeeneticApiError as err:
            if _is_endpoint_missing(err):
                self._traffic_shape_supported = False
                _LOGGER.debug(
                    "ip/traffic-shape endpoint missing — caching as "
                    "unsupported on this firmware"
                )
            else:
                _LOGGER.debug("traffic-shape fetch error: %s", err)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("traffic-shape fetch error: %s", err)

        return {}

    async def async_set_client_bandwidth(self, mac: str, kbps: int) -> None:
        """Set or clear the per-host bandwidth limit for a client.

        Mirrors the ``async_set_client_policy`` shape (CLI commands
        through ``_rci_parse`` followed by ``system configuration
        save``) so the user's running config matches what they'd get
        out of the Keenetic web UI.

        Setting ``kbps > 0`` issues ``ip traffic-shape host <mac> rate
        <kbps>``. Keenetic CLI is idempotent on this command — feeding
        a new rate replaces the previous one in one shot, no separate
        "remove old then add new" dance required.

        Setting ``kbps == 0`` issues ``no ip traffic-shape host <mac>``,
        which removes the whole host entry from the running config —
        equivalent to "no limit" in the web UI. (The shorter ``no ...
        rate`` form is silently dropped by several Keenetic firmwares,
        so we use the entry-level remove for portability.)

        Both paths end with a configuration save so the limit survives
        a router reboot. This is the same persistence guarantee the
        existing policy / block / unblock methods give. Issue #42.
        """
        mac_clean = mac.lower().replace("-", ":")
        safe_mac = _validate_cli_arg(mac_clean, "client mac")

        if kbps <= 0:
            # Removal form. The natural-looking
            # ``no ip traffic-shape host <mac> rate`` is silently
            # ignored on at least some Keenetic firmwares (verified
            # against KN-1xxx/KN-2xxx series during issue #42 testing)
            # — the router accepts the command but the line stays in
            # the running config. Dropping the whole host entry works
            # universally: ``host <mac>`` only ever contains a single
            # ``rate`` field under ``ip traffic-shape``, so there are
            # no other per-host settings to preserve, and the next
            # ``set`` will recreate the entry from scratch.
            cmd = f"no ip traffic-shape host {safe_mac}"
            _LOGGER.debug("Removing bandwidth limit from client %s", mac_clean)
        else:
            # Clamp to a reasonable upper bound to defend against a
            # caller passing a wild value. 10 Gbit/s in kbit/s is
            # already way past anything any home router can shape.
            kbps_clamped = max(1, min(int(kbps), 10_000_000))
            cmd = f"ip traffic-shape host {safe_mac} rate {kbps_clamped}"
            _LOGGER.debug(
                "Setting bandwidth limit on client %s to %d kbit/s",
                mac_clean, kbps_clamped,
            )

        await self._rci_parse(cmd)
        await self._rci_parse("system configuration save")

    async def async_get_lte_data_usage(self) -> Dict[str, Dict[str, Any]]:
        """Get traffic-counter (data usage / monthly quota) for LTE WANs.

        Issue #47: the Keenetic web UI exposes a "Data Usage & Limit"
        page per cellular interface that shows current usage, the
        configured limit, the warning threshold and how many days
        remain until the monthly reset. None of this is derivable
        from the generic byte counters that ship with every WAN
        sub-device, so we surface it as a dedicated sensor set.

        Endpoint shape (verified against firmware via the maintainer's
        router, UsbLte0 on a TurkTelekom plan)::

            GET /rci/show/interface/traffic-counter?name=UsbLte0
            {
              "enabled": true,
              "unit": "GB",
              "value": "48.659",
              "threshold": "72.000",
              "limit": "80.000",
              "remaining": "31.341",
              "days-left": 10,
              "trigger": {"limit": false, "threshold": false},
              "saved": "Thu May 21 21:33:06 2026"
            }

        Returns a mapping of interface id to its parsed counter dict.
        Interfaces without traffic-counter configured, or routers
        without the feature at all, are absent from the result —
        callers should treat that as "feature disabled / unsupported"
        rather than zero usage.

        All numeric strings are converted to GB internally so the
        downstream sensors always speak a single unit, regardless of
        whether the router was set to display in MB, GB or TB.
        """
        if getattr(self, "_traffic_counter_supported", True) is False:
            return {}

        # Locate cellular interfaces. We prefer the trait list because
        # Keenetic firmware traits are stable across versions, but
        # also accept type-name and id-prefix fallbacks for older
        # firmwares where the trait array isn't populated.
        interfaces = await self.async_get_interfaces()
        if not isinstance(interfaces, dict):
            return {}
        iface_dict = interfaces.get("interface", interfaces)
        if not isinstance(iface_dict, dict):
            return {}

        lte_ids: list[str] = []
        for iface_id, iface in iface_dict.items():
            if not isinstance(iface, dict):
                continue
            traits = iface.get("traits") or []
            iface_type = str(iface.get("type") or "").lower()
            iface_id_lower = str(iface_id).lower()
            is_cellular = (
                "UsbLte" in traits
                or "Mobile" in traits
                or "usblte" in iface_type
                or "usbmodem" in iface_type
                or "usbqmi" in iface_type
                or any(tok in iface_id_lower for tok in ("usblte", "usbmodem", "usbqmi"))
            )
            if is_cellular:
                lte_ids.append(str(iface_id))

        if not lte_ids:
            return {}

        results: Dict[str, Dict[str, Any]] = {}
        any_endpoint_seen = False
        for iface_id in lte_ids:
            try:
                data = await self._rci_get(
                    "show/interface/traffic-counter",
                    params={"name": iface_id},
                )
                any_endpoint_seen = True
            except KeeneticApiError as err:
                if _is_endpoint_missing(err):
                    # Per-interface 404 — counter not configured for
                    # this particular interface (user just hasn't
                    # turned it on for the second SIM, say). Skip,
                    # don't disable the feature globally.
                    _LOGGER.debug(
                        "traffic-counter not configured for %s — skipping",
                        iface_id,
                    )
                    continue
                _LOGGER.debug(
                    "traffic-counter fetch error for %s: %s", iface_id, err
                )
                continue
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug(
                    "traffic-counter fetch error for %s: %s", iface_id, err
                )
                continue

            if not isinstance(data, dict) or not data:
                continue
            # Disabled-but-present configs return enabled=false; we
            # still surface the data dict so the user gets a visible
            # "disabled" state on the binary sensor rather than
            # silently absent entities.
            unit = str(data.get("unit") or "GB").upper()
            normalised: Dict[str, Any] = {
                "interface_id": iface_id,
                "enabled": bool(data.get("enabled")),
                "raw_unit": unit,
                # All "amount" fields converted to GB so sensors share
                # a single unit. None passes through as None.
                "used_gb": _data_usage_to_gb(data.get("value"), unit),
                "remaining_gb": _data_usage_to_gb(data.get("remaining"), unit),
                "limit_gb": _data_usage_to_gb(data.get("limit"), unit),
                "threshold_gb": _data_usage_to_gb(data.get("threshold"), unit),
                "days_left": safe_int(data.get("days-left")),
                "limit_exceeded": bool(
                    (data.get("trigger") or {}).get("limit")
                ),
                "threshold_exceeded": bool(
                    (data.get("trigger") or {}).get("threshold")
                ),
                "last_saved": data.get("saved"),
            }
            results[iface_id] = normalised

        # If we never even saw a single successful endpoint response
        # across any LTE interface, the firmware probably doesn't
        # implement this endpoint at all — cache the capability away
        # so we stop polling on every coordinator tick.
        if not any_endpoint_seen and lte_ids:
            self._traffic_counter_supported = False
            _LOGGER.debug(
                "show/interface/traffic-counter endpoint missing on this "
                "firmware — caching as unsupported"
            )

        return results

    async def async_get_lte_sim_slots(self) -> Dict[str, int]:
        """Return the currently configured SIM slot per cellular interface.

        Important quirk that took a round-trip to discover: ``sim``
        means two different things on two different endpoints.

        * ``/rci/show/interface/<id>`` — the status view returns
          ``sim: "READY"`` (or ``"ABSENT"``, ``"PIN_REQUIRED"`` etc.),
          a *string* describing the SIM card's readiness state.
        * ``/rci/interface/<id>`` — the *running config* view returns
          ``sim: {"slot": N}``, the *integer* slot the router is
          configured to talk to.

        We need the second form for the slot dropdown. Issue #51.

        Returns a mapping of interface id to the integer slot
        (1 or 2). Interfaces that don't have an explicit slot
        configured fall back to absent in the dict — the select
        entity then renders as "Unknown" rather than guessing
        a default that might be wrong for dual-SIM modems.
        """
        # Build the list of cellular interfaces from the cached
        # status data we already fetch every tick. Routers without
        # any LTE/USB modem return an empty list and the function
        # short-circuits without making per-interface config calls.
        interfaces = await self.async_get_interfaces()
        if not isinstance(interfaces, dict):
            return {}
        iface_dict = interfaces.get("interface", interfaces)
        if not isinstance(iface_dict, dict):
            return {}

        lte_ids: list[str] = []
        for iface_id, iface in iface_dict.items():
            if not isinstance(iface, dict):
                continue
            traits = iface.get("traits") or []
            iface_type = str(iface.get("type") or "").lower()
            iface_id_lower = str(iface_id).lower()
            is_cellular = (
                "UsbLte" in traits
                or "Mobile" in traits
                or "usblte" in iface_type
                or "usbmodem" in iface_type
                or "usbqmi" in iface_type
                or any(tok in iface_id_lower for tok in ("usblte", "usbmodem", "usbqmi"))
            )
            if is_cellular:
                lte_ids.append(str(iface_id))

        if not lte_ids:
            return {}

        results: Dict[str, int] = {}
        for iface_id in lte_ids:
            try:
                cfg = await self._rci_get(f"interface/{iface_id}")
            except KeeneticApiError as err:
                _LOGGER.debug(
                    "SIM-slot config fetch failed for %s: %s", iface_id, err
                )
                continue
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug(
                    "SIM-slot config fetch failed for %s: %s", iface_id, err
                )
                continue

            if not isinstance(cfg, dict):
                continue
            sim_cfg = cfg.get("sim")
            if not isinstance(sim_cfg, dict):
                continue
            slot = safe_int(sim_cfg.get("slot"))
            if slot is not None:
                results[iface_id] = slot

        return results

    async def async_set_sim_slot(self, interface_id: str, slot: int) -> None:
        """Switch the configured SIM slot on a cellular interface.

        Implements issue #51. Confirmed CLI flow against the
        reporter's UsbQmi0 (Keenetic Giga III, dual-SIM modem):

        1. ``interface <id> sim slot <N>`` — router prints
           ``"<id>": SIM slot is set to "N"`` and the change is
           applied immediately on the live config.
        2. ``system configuration save`` — persists across reboots,
           same pattern as the policy / bandwidth-limit selectors.

        The modem auto-reconnects after the switch (verified via
        ``uptime`` counter restart and ``connected: yes`` in the
        status view), so we don't need to bounce the interface
        down/up manually. A coordinator refresh request after the
        set call is enough to reflect the new slot in HA.
        """
        if slot not in (1, 2):
            raise ValueError(f"SIM slot must be 1 or 2, got {slot}")
        safe_id = _validate_cli_arg(interface_id, "interface id")
        _LOGGER.debug(
            "Switching SIM slot on interface %s to %d", interface_id, slot
        )
        await self._rci_parse(f"interface {safe_id} sim slot {slot}")
        await self._rci_parse("system configuration save")

    async def async_check_firmware_update(self) -> Dict[str, Any]:
        """Check for available firmware update via /rci/show/version."""
        """Check for available firmware update via /rci/show/version."""
        try:
            data = await self._rci_get("show/version")
            if not data:
                return {}

            current = data.get("title") or data.get("release")
            available = data.get("fw-available") or data.get("release-available")

            # Проверяем, есть ли обновление (только stable канал)
            has_update = (
                current and available and
                current != available and
                data.get("fw-update-sandbox") == "stable"
            )

            return {
                "current": {
                    "title": current,
                    "release": data.get("release"),
                },
                "available": {
                    "title": available,
                    "release": data.get("release-available"),
                } if has_update else None,
                "channel": data.get("fw-update-sandbox"),
                "has_update": has_update,
            }
        except Exception as err:
            _LOGGER.debug("Error checking firmware update: %s", err)
            return {}


    async def async_start_firmware_update(self) -> bool:
        """Start firmware update for the controller (main router) ONLY.

        Tries endpoints in order:
        1. /rci/components stage + commit (KeeneticOS 5.x)
        2. /rci/system/update (older firmware)
        Does NOT use mws/update/start as that triggers a mesh-wide update.
        """
        # Try KeeneticOS 5.x: stage components then commit
        try:
            version_data = await self._rci_get("show/version")
            ndw_components = ""
            if isinstance(version_data, dict):
                ndw_components = version_data.get("ndw", {}).get("components", "")

            if ndw_components:
                current_components = [
                    c.strip() for c in ndw_components.split(",") if c.strip()
                ]
                install_list = [{"component": c} for c in current_components]
                payload = [{"components": {"install": install_list}}]

                _LOGGER.debug("Staging component update on controller")
                await self._request("POST", f"{RCI_ROOT}/", json=payload)

                _LOGGER.debug("Committing component update on controller")
                await self._rci_post("components/commit", {"reason": "manual"})
                _LOGGER.info("Controller firmware update started via components/commit")
                return True
        except KeeneticApiError as err:
            if "404" not in str(err):
                raise HomeAssistantError(f"Failed to start update: {err}") from err
            _LOGGER.debug("Components update not available, trying system/update")

        # Try system/update (older firmware)
        try:
            result = await self._rci_post("system/update", {"confirm": True})
            if isinstance(result, dict):
                status = result.get("status") or result.get("result")
                if status in ("started", "ok", True, "accepted"):
                    _LOGGER.info("Controller firmware update started via system/update")
                    return True
            if result is not None:
                _LOGGER.info("Controller firmware update started via system/update")
                return True
        except KeeneticApiError as err:
            if "404" not in str(err):
                raise HomeAssistantError(f"Failed to start update: {err}") from err
            _LOGGER.debug("system/update returned 404")

        msg = "No compatible firmware update endpoint found on this router"
        _LOGGER.error(msg)
        raise HomeAssistantError(msg)

    async def async_start_node_firmware_update(
        self, node_ip: str, node_name: str = ""
    ) -> bool:
        """Start firmware update on a specific mesh node by connecting directly.

        Connects to the node's own RCI API and triggers its local update.
        Always uses challenge auth since mesh nodes may not accept Basic Auth
        even when the controller does.

        Args:
            node_ip: IP address of the mesh node.
            node_name: Display name for logging.
        """
        if not self._session or not node_ip:
            raise HomeAssistantError("Cannot connect to mesh node")

        label = node_name or node_ip
        scheme = "https" if self._ssl else "http"

        # Try controller's port first, then default port 80
        ports_to_try = [self._port]
        if self._port != 80:
            ports_to_try.append(80)

        for port in ports_to_try:
            base = f"{scheme}://{node_ip}:{port}"

            # Always do challenge auth with mesh nodes
            node_headers = await self._authenticate_to_node(node_ip, port)
            if not node_headers:
                _LOGGER.debug(
                    "Could not authenticate to node %s on port %s", label, port
                )
                continue

            # KeeneticOS 5.x: two-step update via components
            # Step 1: Get current components from show/version
            try:
                url = f"{base}{RCI_ROOT}/show/version"
                async with async_timeout.timeout(self._request_timeout):
                    resp = await self._session.get(url, headers=node_headers)
                if resp.status == 200:
                    version_data = await resp.json()
                    ndw_components = version_data.get("ndw", {}).get("components", "")
                    if ndw_components:
                        current_components = [
                            c.strip() for c in ndw_components.split(",") if c.strip()
                        ]
                        _LOGGER.debug(
                            "Node %s has %d components: %s",
                            label, len(current_components), current_components,
                        )

                        # Step 2: POST component list to /rci/
                        install_list = [
                            {"component": c} for c in current_components
                        ]
                        payload = [{"components": {"install": install_list}}]

                        url = f"{base}{RCI_ROOT}/"
                        _LOGGER.info(
                            "Staging component update on node %s", label
                        )
                        async with async_timeout.timeout(self._request_timeout):
                            resp = await self._session.post(
                                url,
                                json=payload,
                                headers=node_headers,
                            )
                        if resp.status not in (200, 204):
                            text = await resp.text()
                            _LOGGER.warning(
                                "Node %s component staging returned %s: %s",
                                label, resp.status, text,
                            )

                        # Step 3: Commit
                        url = f"{base}{RCI_ROOT}/components/commit"
                        _LOGGER.info(
                            "Committing update on node %s", label
                        )
                        async with async_timeout.timeout(self._request_timeout):
                            resp = await self._session.post(
                                url,
                                json={"reason": "manual"},
                                headers=node_headers,
                            )
                        if resp.status in (200, 204):
                            _LOGGER.info(
                                "Node %s firmware update started via "
                                "components/commit",
                                label,
                            )
                            return True

                        text = await resp.text()
                        _LOGGER.warning(
                            "Node %s commit returned %s: %s",
                            label, resp.status, text,
                        )
                    else:
                        _LOGGER.debug(
                            "Node %s has no ndw.components in version info",
                            label,
                        )
                elif resp.status == 401:
                    _LOGGER.debug("Auth rejected on node %s port %s", label, port)
                    continue
            except asyncio.TimeoutError:
                _LOGGER.debug("Timeout connecting to node %s port %s", label, port)
                continue
            except Exception as err:
                _LOGGER.debug(
                    "Components update on node %s failed: %s", label, err
                )

            # Fallback: POST /rci/system/update (older firmware)
            try:
                url = f"{base}{RCI_ROOT}/system/update"
                _LOGGER.info("Attempting update on node %s via %s", label, url)
                async with async_timeout.timeout(self._request_timeout):
                    resp = await self._session.post(
                        url,
                        json={"confirm": True},
                        headers=node_headers,
                    )
                if resp.status in (200, 204):
                    _LOGGER.info(
                        "Node %s firmware update started via system/update", label
                    )
                    return True
                if resp.status != 404:
                    text = await resp.text()
                    _LOGGER.debug(
                        "Node %s system/update returned %s: %s",
                        label, resp.status, text,
                    )
            except asyncio.TimeoutError:
                _LOGGER.debug("Timeout on system/update for node %s", label)
            except Exception as err:
                _LOGGER.debug("system/update on node %s failed: %s", label, err)

        msg = f"Could not start firmware update on node {label}"
        _LOGGER.error(msg)
        raise HomeAssistantError(msg)

    async def _authenticate_to_node(
        self, node_ip: str, port: int | None = None
    ) -> Dict[str, str] | None:
        """Perform NDW2 challenge auth against a specific mesh node.

        Always attempts challenge auth first since mesh nodes typically
        require it, even when the controller uses Basic Auth.

        Returns headers dict with session cookie, or None if auth failed.
        """
        if port is None:
            port = self._port

        scheme = "https" if self._ssl else "http"
        auth_url = f"{scheme}://{node_ip}:{port}/auth"

        try:
            # Step 1: GET /auth to get challenge
            async with async_timeout.timeout(self._request_timeout):
                get_resp = await self._session.get(
                    auth_url, allow_redirects=False
                )

            challenge = get_resp.headers.get("X-NDM-Challenge")
            realm = get_resp.headers.get("X-NDM-Realm", "")

            if not challenge:
                _LOGGER.debug(
                    "Node %s did not return challenge header, "
                    "trying basic auth fallback",
                    node_ip,
                )
                return dict(self._auth_header or {})

            # Step 2: Compute hash
            ha1 = hashlib.md5(
                f"{self._username}:{realm}:{self._password}".encode()
            ).hexdigest()
            response_hash = hashlib.sha256(
                (challenge + ha1).encode()
            ).hexdigest()

            # Extract session cookie
            raw_cookie = get_resp.headers.get("Set-Cookie", "")
            session_cookie = None
            if raw_cookie:
                cookie_kv = raw_cookie.split(";")[0].strip()
                if "=" in cookie_kv:
                    session_cookie = cookie_kv

            # Step 3: POST /auth with credentials
            post_headers: Dict[str, str] = {}
            if session_cookie:
                post_headers["Cookie"] = session_cookie

            async with async_timeout.timeout(self._request_timeout):
                post_resp = await self._session.post(
                    auth_url,
                    json={"login": self._username, "password": response_hash},
                    headers=post_headers,
                )

            if post_resp.status in (200, 204):
                _LOGGER.debug(
                    "Challenge auth to node %s:%s succeeded", node_ip, port
                )
                return {"Cookie": session_cookie} if session_cookie else {}

            _LOGGER.debug(
                "Challenge auth to node %s:%s returned status %s",
                node_ip, port, post_resp.status,
            )
            return None

        except asyncio.TimeoutError:
            _LOGGER.debug("Timeout during auth to node %s:%s", node_ip, port)
            return None
        except Exception as err:
            _LOGGER.debug(
                "Auth to node %s:%s failed: %s", node_ip, port, err
            )
            return None


    async def async_get_update_progress(self) -> Dict[str, Any]:
        """Get current update progress (if in progress).

        Returns progress info or empty dict if no update running.
        """
        try:
            data = await self._rci_get("system/update/status")
            if not data or not isinstance(data, dict):
                return {}

            return {
                "in_progress": data.get("in-progress", False),
                "progress_percent": data.get("progress", 0),
                "stage": data.get("stage"),
                "eta_seconds": data.get("eta"),
            }
        except Exception:
            return {}

    async def async_get_ndns_info(self) -> Dict[str, Any]:
        """Get NDNS (Dynamic DNS) information from /rci/show/ndns.

        Returns detailed information about NDNS configuration and tunnels.
        Example response includes:
        - name: Hostname
        - domain: Domain name
        - access: Access type (cloud, etc.)
        - ttp: Tunnel information with tunnel list
        - updated: Last update status
        - address/address6: IP addresses
        """
        # Capability gate: routers without KeenDNS / NDNS enabled
        # answer 404 every poll. Cache the result once we know.
        if self._ndns_supported is False:
            return {}

        try:
            data = await self._rci_get("show/ndns")
        except KeeneticApiError as err:
            if _is_endpoint_missing(err):
                _LOGGER.debug(
                    "show/ndns not supported on this router, "
                    "caching as absent"
                )
                self._ndns_supported = False
                return {}
            _LOGGER.debug("Error getting NDNS info: %s", err)
            return {}
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Error getting NDNS info: %s", err)
            return {}

        if not data:
            return {}

        # First successful response — pin capability.
        self._ndns_supported = True

        try:
            # Ensure we always return a dict
            result = dict(data) if isinstance(data, dict) else {}

            # Parse tunnel information if present
            if "ttp" in result and isinstance(result["ttp"], dict):
                ttp = result["ttp"]
                # Ensure tunnel list is properly formatted
                if "tunnel" in ttp and isinstance(ttp["tunnel"], list):
                    tunnels = []
                    for tunnel in ttp["tunnel"]:
                        if isinstance(tunnel, dict):
                            # Convert string numbers to int where appropriate
                            for key in ["uptime", "idle", "timeout", "linger"]:
                                if key in tunnel and tunnel[key] is not None:
                                    try:
                                        tunnel[key] = int(tunnel[key])
                                    except (ValueError, TypeError):
                                        pass
                            tunnels.append(tunnel)
                    ttp["tunnel"] = tunnels

            # NDNS payload contains the user's KeenDNS hostname/domain —
            # log only structural keys instead of the full body so a
            # raised debug level cannot leak the operator's identity.
            _LOGGER.debug("NDNS info retrieved (keys=%s)", list(result.keys()))
            return result

        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Error parsing NDNS info: %s", err)
            return {}

    # =================== DNS Proxy diagnostics ===================

    @staticmethod
    def _redact_doh_uri(value: Any) -> str:
        """Strip path/query/userinfo from a DNS-over-HTTPS upstream URI.

        Personalised DoH endpoints (NextDNS, ControlD, etc.) embed the
        operator's account ID in the URI path:

            https://dns.nextdns.io/abc123xyz

        Surfacing that path in HA state, attributes, or a diagnostics
        dump is effectively a credential leak. This helper returns the
        URI reduced to just ``scheme://host[:port]/`` so the proxy is
        identifiable but the account ID stays private.
        """
        from urllib.parse import urlsplit, urlunsplit
        text = str(value or "").strip()
        if not text:
            return ""
        try:
            parts = urlsplit(text)
        except ValueError:
            return ""
        host = parts.hostname or ""
        try:
            port = parts.port
        except ValueError:
            # Malformed port — strip the URI entirely rather than
            # propagate something that other code might choke on.
            return ""
        if port:
            host = f"{host}:{port}"
        if not host:
            return ""
        return urlunsplit((parts.scheme or "https", host, "/", "", ""))

    async def async_get_dns_proxy_status(self) -> Dict[str, Any]:
        """Return a summary of the router's DNS proxy + DoH upstream health.

        Returns a dict shaped like:
            {
                "status": "ok" | "degraded" | "down" | "unknown",
                "proxy_count": int,
                "doh_server_count": int,
                "dns_server_count": int,
                "active_dns_server_count": int,
                "requests_sent": int,
                "failed_requests": int,
                "proxies": [<redacted upstream URI>, ...],
                "client_path_uses_doh": bool | None,
            }

        Returns ``{}`` (empty dict) when the router doesn't expose the
        DNS proxy endpoint (older firmwares, models without DoH
        support) — the capability is cached so subsequent ticks don't
        re-poll the missing endpoint.
        """
        if self._dns_proxy_supported is False:
            return {}

        try:
            data = await self._rci_get("show/dns-proxy") or {}
        except KeeneticApiError as err:
            if _is_endpoint_missing(err):
                _LOGGER.debug(
                    "show/dns-proxy not supported, caching as absent"
                )
                self._dns_proxy_supported = False
                return {}
            _LOGGER.debug("dns-proxy fetch failed: %s", err)
            return {}
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("dns-proxy fetch unexpected error: %s", err)
            return {}

        self._dns_proxy_supported = True

        if not isinstance(data, dict):
            return {}

        # ----- Proxy / upstream enumeration -----
        # The router can return the upstream list as either a list or
        # a single dict when only one upstream is configured (firmware
        # quirk). Normalise to a list of dicts.
        raw_proxies = data.get("proxy") or data.get("proxies") or []
        if isinstance(raw_proxies, dict):
            raw_proxies = [raw_proxies]
        if not isinstance(raw_proxies, list):
            raw_proxies = []

        doh_count = 0
        dns_count = 0
        active_dns = 0
        proxy_uris: list[str] = []
        client_path_uses_doh: bool | None = None

        for proxy in raw_proxies:
            if not isinstance(proxy, dict):
                continue

            uri = proxy.get("uri") or proxy.get("url")
            proto = str(proxy.get("type") or proxy.get("protocol") or "").lower()
            is_doh = "doh" in proto or (
                isinstance(uri, str) and uri.lower().startswith("https://")
            )

            if uri:
                proxy_uris.append(self._redact_doh_uri(uri))

            if is_doh:
                doh_count += 1
            else:
                dns_count += 1
                if proxy.get("active") in (True, "true", "yes", 1, "1"):
                    active_dns += 1

            # The "client path" is the upstream we're actually using for
            # client DNS queries — if any of them is DoH, the client
            # path effectively goes through DoH.
            if is_doh and proxy.get("active") in (True, "true", "yes", 1, "1"):
                client_path_uses_doh = True

        if doh_count == 0 and client_path_uses_doh is None:
            client_path_uses_doh = False

        proxy_count = doh_count + dns_count

        # ----- Counters -----
        stats = data.get("statistics") or data.get("stats") or {}
        if not isinstance(stats, dict):
            stats = {}
        try:
            requests_sent = int(stats.get("requests-sent")
                                or stats.get("requests_sent")
                                or stats.get("sent") or 0)
        except (TypeError, ValueError):
            requests_sent = 0
        try:
            failed_requests = int(stats.get("requests-failed")
                                  or stats.get("requests_failed")
                                  or stats.get("failed") or 0)
        except (TypeError, ValueError):
            failed_requests = 0

        # ----- Status rollup -----
        # ok        -> ≥1 proxy and (DoH active OR ≥1 active DNS)
        # degraded  -> ≥1 proxy but no active upstream
        # down      -> 0 proxies configured
        # unknown   -> couldn't make sense of the payload
        if proxy_count == 0:
            status = "down"
        elif (doh_count > 0 and client_path_uses_doh) or active_dns > 0:
            status = "ok"
        else:
            status = "degraded"

        return {
            "status": status,
            "proxy_count": proxy_count,
            "doh_server_count": doh_count,
            "dns_server_count": dns_count,
            "active_dns_server_count": active_dns,
            "requests_sent": requests_sent,
            "failed_requests": failed_requests,
            "proxies": proxy_uris,
            "client_path_uses_doh": client_path_uses_doh,
        }

    # =================== IPsec VICI log diagnostics ===================

    async def async_get_ipsec_diagnostics(self) -> Dict[str, Any]:
        """Scan the router's recent log for IPsec VICI failure markers.

        Specific firmware-bug shape we care about:

            IpSec::Vici::Stats: out of memory

        These messages indicate the strongSwan VICI socket has run out
        of buffer space and IPsec status queries are dropping silently
        — tunnels stay up but the integration's IPsec sensors stop
        reflecting reality. Surfacing the recent count gives the user
        an early warning without forcing them to SSH into the router
        and grep log files manually.

        Returns ``{}`` when the log endpoint isn't reachable; otherwise
        a dict shaped like:
            {
                "status": "ok" | "warning",
                "vici_out_of_memory_count": int,
                "last_vici_out_of_memory": str | None,  # ISO-ish timestamp from log
                "last_error_code": int | None,
                "recent_matches": [str, ...],
                "scanned_log_lines": int,
                "command": str,
            }
        """
        if self._ipsec_diagnostics_supported is False:
            return {}

        log_cmd = "show log"
        try:
            data = await self._rci_parse(log_cmd)
        except KeeneticApiError as err:
            if _is_endpoint_missing(err):
                _LOGGER.debug(
                    "show log unavailable, IPsec VICI diagnostics disabled"
                )
                self._ipsec_diagnostics_supported = False
                return {}
            _LOGGER.debug("IPsec diagnostics fetch failed: %s", err)
            return {}
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("IPsec diagnostics unexpected error: %s", err)
            return {}

        self._ipsec_diagnostics_supported = True

        # `_rci_parse` returns a heterogeneous structure — strings,
        # dicts with "message" keys, lists of those, etc. Normalise to
        # a flat list of log lines.
        log_lines: list[str] = []
        if isinstance(data, str):
            log_lines = data.splitlines()
        elif isinstance(data, dict):
            messages = self._extract_log_messages(data)
            log_lines.extend(messages)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    log_lines.append(item)
                elif isinstance(item, dict):
                    log_lines.extend(self._extract_log_messages(item))

        # Cap the scan — old router logs can be megabytes. We only
        # care about the recent tail.
        TAIL = 2000
        if len(log_lines) > TAIL:
            log_lines = log_lines[-TAIL:]

        recent_matches: list[str] = []
        last_match: str | None = None
        last_timestamp: str | None = None
        last_error_code: int | None = None

        marker = "IpSec::Vici::Stats: out of memory"
        for line in log_lines:
            if marker.lower() in line.lower():
                recent_matches.append(line)
                last_match = line
                # Crude timestamp extraction — Keenetic log lines start
                # with a "YYYY-MM-DD HH:MM:SS" or similar prefix. We
                # keep the first 19 chars as the best-effort timestamp.
                if len(line) >= 19:
                    last_timestamp = line[:19]

        # Look for a trailing "errno=N" or "(error N)" pattern on the
        # last match to surface the actual error code.
        if last_match:
            import re as _re
            m = _re.search(r"err(?:no)?\s*=?\s*(\d+)", last_match)
            if m:
                try:
                    last_error_code = int(m.group(1))
                except ValueError:
                    pass

        status = "warning" if recent_matches else "ok"

        return {
            "status": status,
            "vici_out_of_memory_count": len(recent_matches),
            "last_vici_out_of_memory": last_timestamp,
            "last_error_code": last_error_code,
            # Cap the surfaced lines too — log lines can be long and
            # there's no point putting 100 matches into a state
            # attribute.
            "recent_matches": recent_matches[-10:],
            "scanned_log_lines": len(log_lines),
            "command": log_cmd,
        }

    @staticmethod
    def _extract_log_messages(payload: Dict[str, Any]) -> list[str]:
        """Flatten a `show log` dict response into individual lines.

        Keenetic firmware versions disagree on the response shape:
        some return ``{"log": [{"message": "..."}, ...]}``, others
        ``{"message": "..."}`` for a single line, others a string-keyed
        nested dict. Walk all of them defensively.
        """
        lines: list[str] = []
        log = payload.get("log")
        if isinstance(log, list):
            for entry in log:
                if isinstance(entry, dict):
                    msg = entry.get("message") or entry.get("msg")
                    if isinstance(msg, str):
                        lines.append(msg)
                elif isinstance(entry, str):
                    lines.append(entry)
        elif isinstance(log, dict):
            msg = log.get("message") or log.get("msg")
            if isinstance(msg, str):
                lines.append(msg)
        # Top-level message field (single-line responses)
        top = payload.get("message")
        if isinstance(top, str):
            lines.append(top)
        return lines
