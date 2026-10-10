"""KeeneticOS 5.2 interactive sign-in (``x-ndw4-interactive``).

KeeneticOS 5.2 moved web sign-in to a SCRAM-style handshake built on
Argon2id and HMAC-SHA3-512. Once a router has migrated its password
storage it rejects the older NDW2 challenge even for the right password,
while still advertising it (issue #71). This module is the client side
of the new handshake.

The protocol is not officially documented. This implementation follows
PR #68 by @asustek1978, verified on a Netcraze Ultra NC-1812, and was
cross-checked against two independent open-source clients — Eralde's
rci-tools (ISC) and hoaxisr's awg-manager (MIT). No code was copied
from either; all three agree on the message format, key derivation and
key labels.

No Argon2 implementation is imported at module load. The handshake only
runs against routers that advertise it, so a missing backend must never
stop the integration from loading for everyone else.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from typing import Any, Mapping, Optional, Tuple

import aiohttp

_LOGGER = logging.getLogger(__name__)

SCHEME = "x-ndw4-interactive"

_CLIENT_KEY_LABEL = b"NDW4 Interactive Client Key"
_SERVER_KEY_LABEL = b"NDW4 Interactive Server Key"

# Bounds on the Argon2id cost the router may ask for. Wide enough for any
# sane firmware value, tight enough that a bogus reply can't make Home
# Assistant allocate gigabytes or spin for minutes.
_ITER_RANGE = (1, 64)
_MEMCOST_KIB_RANGE = (8, 262144)

# The router names the endpoint to POST the handshake to, and it is
# appended to our own base URL. Only a plain absolute path is accepted,
# so a reply can't steer the exchange to another host.
_ENDPOINT_RE = re.compile(r"/(?!/)[A-Za-z0-9._~/-]*")


class Ndw4Error(Exception):
    """NDW4 sign-in failed."""


class Ndw4CredentialsError(Ndw4Error):
    """The router refused the user name or password.

    Definitive: falling back to another scheme would only add a failed
    login towards the router's brute-force ban.
    """


class Ndw4BackendError(Ndw4Error):
    """No Argon2id implementation is available on this system."""


class Ndw4ProtocolError(Ndw4Error):
    """The router's reply did not follow the handshake as understood.

    Says nothing about the credentials, so a caller may retry or try
    another scheme the router offers.
    """


def parse_offer(headers: Mapping[str, str]) -> Tuple[bool, Optional[str]]:
    """Return ``(offered, endpoint)`` from a GET /auth reply.

    ``endpoint`` is None when the scheme is offered with a missing or
    unsafe endpoint; the caller should treat that as a protocol failure
    rather than as "not offered".
    """
    for value in _header_values(headers, "WWW-Authenticate"):
        scheme, _, params = (value or "").strip().partition(" ")
        if scheme.lower() != SCHEME:
            continue
        match = re.search(r'endpoint="([^"]*)"', params)
        endpoint = match.group(1) if match else ""
        if _ENDPOINT_RE.fullmatch(endpoint):
            return True, endpoint
        return True, None
    return False, None


async def async_login(
    session: aiohttp.ClientSession,
    base_url: str,
    endpoint: str,
    username: str,
    password: str,
    cookie: Optional[str],
    timeout: float,
) -> str:
    """Run the three-phase handshake and return the session cookie.

    ``cookie`` is the ``name=value`` pair from the GET /auth that
    advertised the scheme; the handshake is bound to that session.
    Transport errors (``aiohttp.ClientError``, ``TimeoutError``)
    propagate unchanged for the caller to classify.
    """
    if not cookie:
        raise Ndw4ProtocolError("router did not set a session cookie")

    base_url = base_url.rstrip("/")
    auth_url = f"{base_url}{endpoint}"
    started = time.monotonic()
    client_nonce = base64.b64encode(secrets.token_bytes(16)).decode("ascii")

    # Phase 1 — announce ourselves, receive salt, Argon2 cost and the
    # combined nonce.
    status, headers, cookie = await _request(
        session,
        "POST",
        auth_url,
        {"login": username, "nonce": client_nonce},
        cookie,
        timeout,
    )
    reply = _reply_data(headers)
    if reply is None:
        if status == 401:
            # How the router answers a user name it doesn't know.
            raise Ndw4CredentialsError("router refused the user name")
        raise Ndw4ProtocolError(f"phase 1: HTTP {status} without X-NDM-Data")
    _raise_on_error_field(reply, "phase 1")

    salt_b64 = _text(reply, "salt", "phase 1")
    combined_nonce = _text(reply, "nonce", "phase 1")
    if not combined_nonce.startswith(client_nonce) or combined_nonce == client_nonce:
        raise Ndw4ProtocolError("phase 1: server nonce does not extend ours")
    salt = _b64decode(salt_b64, "salt")
    if len(salt) != 16:
        raise Ndw4ProtocolError("phase 1: salt is not 16 bytes")
    iter_raw, iterations = _cost(reply.get("iter"), "iter", _ITER_RANGE)
    mem_raw, memory_kib = _cost(reply.get("memcost"), "memcost", _MEMCOST_KIB_RANGE)

    # Cost values are signed exactly as the router sent them.
    auth_message = (
        f"login1={username},nonce1={client_nonce};"
        f"iter2={iter_raw},memcost2={mem_raw},"
        f"nonce2={combined_nonce},salt2={salt_b64};"
        f"login3={username},nonce3={combined_nonce}"
    )

    derive_started = time.monotonic()
    client_key, stored_key, server_key = await asyncio.to_thread(
        _derive_keys, password.encode("utf-8"), salt, iterations, memory_kib
    )
    _LOGGER.debug(
        "NDW4 Argon2id: iter=%s memcost=%s KiB took %.0f ms",
        iterations,
        memory_kib,
        (time.monotonic() - derive_started) * 1000,
    )

    # Phase 2 — send our proof, receive the router's signature.
    status, headers, cookie = await _request(
        session,
        "POST",
        auth_url,
        {
            "login": username,
            "nonce": combined_nonce,
            "proof": _proof(client_key, stored_key, auth_message),
        },
        cookie,
        timeout,
    )
    reply = _reply_data(headers)
    if reply is None:
        # A wrong password still gets a signature (below), so a reply
        # without one is a protocol problem — an expired session, say.
        raise Ndw4ProtocolError(f"phase 2: HTTP {status} without X-NDM-Data")
    _raise_on_error_field(reply, "phase 2")

    signature_b64 = _text(reply, "signature", "phase 2")
    signature = _b64decode(signature_b64, "signature")
    if not hmac.compare_digest(signature, _hmac(server_key, auth_message.encode())):
        # The router answers a wrong password with its genuine signature,
        # which can't match keys derived from the wrong password. (The
        # one other cause would be something impersonating the router;
        # either way the session is abandoned before phase 3.)
        raise Ndw4CredentialsError("router refused the password")

    # Phase 3 — acknowledge the verified signature.
    signature_message = f"{auth_message};signature4={signature_b64}"
    status, headers, cookie = await _request(
        session,
        "POST",
        auth_url,
        {
            "login": username,
            "nonce": combined_nonce,
            "signature-proof": _proof(client_key, stored_key, signature_message),
        },
        cookie,
        timeout,
    )
    if status != 200:
        # The signature already proved the password right.
        raise Ndw4ProtocolError(f"phase 3: HTTP {status}")

    # Confirm the session is really authenticated before handing it out.
    status, _headers, cookie = await _request(
        session, "GET", f"{base_url}/auth", None, cookie, timeout
    )
    if status != 200:
        raise Ndw4ProtocolError(f"session check after sign-in: HTTP {status}")

    _LOGGER.debug("NDW4 sign-in succeeded in %.1f s", time.monotonic() - started)
    return cookie


def _derive_keys(
    password: bytes, salt: bytes, iterations: int, memory_kib: int
) -> Tuple[bytes, bytes, bytes]:
    """Return (client_key, stored_key, server_key). Runs in a worker thread."""
    try:
        salted = _argon2id(password, salt, iterations, memory_kib)
    except MemoryError as err:
        raise Ndw4BackendError(
            f"not enough memory for Argon2id (memcost={memory_kib} KiB)"
        ) from err
    client_key = _hmac(salted, _CLIENT_KEY_LABEL)
    server_key = _hmac(salted, _SERVER_KEY_LABEL)
    return client_key, hashlib.sha3_512(client_key).digest(), server_key


def _argon2id(password: bytes, salt: bytes, iterations: int, memory_kib: int) -> bytes:
    """Argon2id (version 0x13), 64-byte output, one lane.

    Prefers ``cryptography``, which Home Assistant ships (Argon2id since
    44.0, i.e. HA 2025.1; its wheels bundle a new enough OpenSSL), and
    falls back to ``argon2-cffi`` if installed. Both give identical
    output for identical parameters.
    """
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    except ImportError:
        pass
    else:
        try:
            kdf = Argon2id(
                salt=salt,
                length=64,
                iterations=iterations,
                lanes=1,
                memory_cost=memory_kib,
            )
        except UnsupportedAlgorithm:
            # cryptography built against OpenSSL < 3.2, or FIPS mode.
            pass
        else:
            return kdf.derive(password)

    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as err:
        raise Ndw4BackendError(
            "no Argon2id implementation available — needs the 'cryptography' "
            "package (44+, OpenSSL 3.2+) or 'argon2-cffi'"
        ) from err
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=iterations,
        memory_cost=memory_kib,
        parallelism=1,
        hash_len=64,
        type=Type.ID,
        version=19,
    )


def _hmac(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha3_512).digest()


def _proof(client_key: bytes, stored_key: bytes, message: str) -> str:
    """ClientKey XOR HMAC(StoredKey, message), base64 — the SCRAM proof."""
    signature = _hmac(stored_key, message.encode("utf-8"))
    return base64.b64encode(
        bytes(a ^ b for a, b in zip(client_key, signature))
    ).decode("ascii")


async def _request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    payload: Optional[dict],
    cookie: Optional[str],
    timeout: float,
) -> Tuple[int, Mapping[str, str], Optional[str]]:
    """One handshake round-trip; returns (status, headers, cookie).

    The cookie travels in an explicit header because Home Assistant's
    shared CookieJar ignores cookies from bare IP addresses, which is
    how most people address their router. A refreshed Set-Cookie
    replaces it.
    """
    headers = {"Cookie": cookie} if cookie else {}
    async with asyncio.timeout(timeout):
        async with session.request(
            method, url, json=payload, headers=headers, allow_redirects=False
        ) as resp:
            await resp.read()
            reply_headers = resp.headers
            status = resp.status
    _LOGGER.debug("NDW4 %s %s -> HTTP %s", method, url, status)
    return status, reply_headers, session_cookie(reply_headers) or cookie


def _reply_data(headers: Mapping[str, str]) -> Optional[dict]:
    """Decode X-NDM-Data (base64 JSON). None when the header is absent."""
    encoded = headers.get("X-NDM-Data")
    if not encoded:
        return None
    try:
        data = json.loads(base64.b64decode(encoded, validate=True).decode("utf-8"))
    except (binascii.Error, ValueError) as err:
        raise Ndw4ProtocolError("X-NDM-Data is not base64-encoded JSON") from err
    if not isinstance(data, dict):
        raise Ndw4ProtocolError("X-NDM-Data is not a JSON object")
    return data


def _raise_on_error_field(reply: dict, stage: str) -> None:
    message = reply.get("error") or reply.get("e")
    if isinstance(message, str) and message:
        # The router explicitly refused this step of the sign-in.
        raise Ndw4CredentialsError(f"{stage}: {message}")


def _text(reply: dict, key: str, stage: str) -> str:
    value = reply.get(key)
    if not isinstance(value, str) or not value:
        raise Ndw4ProtocolError(f"{stage}: missing '{key}'")
    return value


def _cost(value: Any, key: str, bounds: Tuple[int, int]) -> Tuple[str, int]:
    """Validate an Argon2 cost, keeping the exact decimal form to sign."""
    if isinstance(value, bool):
        raise Ndw4ProtocolError(f"invalid {key}")
    if isinstance(value, int):
        raw, parsed = str(value), value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        raw, parsed = value, int(value)
    else:
        raise Ndw4ProtocolError(f"invalid {key}")
    if not bounds[0] <= parsed <= bounds[1]:
        raise Ndw4ProtocolError(f"{key}={parsed} outside {bounds[0]}..{bounds[1]}")
    return raw, parsed


def _b64decode(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as err:
        raise Ndw4ProtocolError(f"{label} is not valid base64") from err


def _header_values(headers: Mapping[str, str], name: str) -> list:
    """Every value of a repeated header — KeeneticOS 5.2 sends two
    WWW-Authenticate lines, and ``dict()`` / ``get()`` keep only one."""
    getall = getattr(headers, "getall", None)
    if getall is not None:
        return list(getall(name, []))
    value = headers.get(name)
    return [value] if value else []


def session_cookie(headers: Mapping[str, str]) -> Optional[str]:
    """The first ``name=value`` pair from Set-Cookie, attributes dropped."""
    for raw in _header_values(headers, "Set-Cookie"):
        pair = (raw or "").split(";", 1)[0].strip()
        if "=" in pair:
            return pair
    return None
