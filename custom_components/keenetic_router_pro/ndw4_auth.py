"""Interactive Keenetic/Netcraze authentication helpers.

Supports the modern ``x-ndw4-interactive`` authentication scheme
(SCRAM-SHA3-512 with Argon2id) and keeps ``x-ndw2-interactive`` as a
fallback for older devices.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
from typing import Any

import aiohttp
from argon2.low_level import Type, hash_secret_raw


class InteractiveAuthError(Exception):
    """Interactive router authentication failed."""


_NDW4 = "x-ndw4-interactive"
_NDW2 = "x-ndw2-interactive"


def _www_auth_values(response: aiohttp.ClientResponse) -> list[str]:
    """Return every WWW-Authenticate header value."""
    try:
        return list(response.headers.getall("WWW-Authenticate", []))
    except Exception:  # pragma: no cover - defensive for unusual mappings
        value = response.headers.get("WWW-Authenticate")
        return [value] if value else []


def _extract_cookie(response: aiohttp.ClientResponse) -> str | None:
    """Return the first ``name=value`` pair from Set-Cookie.

    Home Assistant's shared aiohttp CookieJar uses ``unsafe=False`` and
    therefore intentionally ignores cookies from bare IP addresses. Local
    router installs commonly use an IPv4 literal, so interactive auth must
    carry the session cookie explicitly between handshake phases and later
    RCI calls.
    """
    try:
        values = list(response.headers.getall("Set-Cookie", []))
    except Exception:  # pragma: no cover - defensive for unusual mappings
        value = response.headers.get("Set-Cookie")
        values = [value] if value else []

    for raw in values:
        if not raw:
            continue
        pair = raw.split(";", 1)[0].strip()
        if "=" in pair:
            return pair
    return None


def _find_endpoint(values: list[str], scheme: str) -> str | None:
    """Extract an interactive auth endpoint from WWW-Authenticate."""
    for value in values:
        if scheme not in value:
            continue
        match = re.search(r'endpoint="([^"]+)"', value)
        if match:
            return match.group(1)
    return None


def _decode_reply_header(
    response: aiohttp.ClientResponse,
    stage: str,
) -> dict[str, Any]:
    """Decode the base64 JSON object returned in X-NDM-Data."""
    encoded = response.headers.get("X-NDM-Data")
    if not encoded:
        raise InteractiveAuthError(
            f"NDW4 {stage}: router did not return X-NDM-Data "
            f"(HTTP {response.status})"
        )

    try:
        raw = base64.b64decode(encoded, validate=True)
        payload = json.loads(raw.decode("utf-8"))
    except Exception as err:
        raise InteractiveAuthError(
            f"NDW4 {stage}: invalid X-NDM-Data payload"
        ) from err

    if not isinstance(payload, dict):
        raise InteractiveAuthError(f"NDW4 {stage}: invalid reply object")

    message = payload.get("error") or payload.get("e")
    if isinstance(message, str) and message:
        raise InteractiveAuthError(f"NDW4 {stage}: {message}")

    return payload


def _require_text(payload: dict[str, Any], key: str, stage: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise InteractiveAuthError(f"NDW4 {stage}: missing {key}")
    return value


def _cost(
    value: Any,
    key: str,
    low: int,
    high: int,
) -> tuple[str, int]:
    """Validate an Argon2 cost and preserve its original decimal form."""
    if isinstance(value, bool):
        raise InteractiveAuthError(f"NDW4: invalid {key}")

    if isinstance(value, int):
        raw = str(value)
        parsed = value
    elif isinstance(value, str) and value.isdigit():
        raw = value
        parsed = int(value)
    else:
        raise InteractiveAuthError(f"NDW4: invalid {key}")

    if parsed < low or parsed > high:
        raise InteractiveAuthError(f"NDW4: {key} out of range")

    return raw, parsed


def _b64decode(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as err:
        raise InteractiveAuthError(
            f"NDW4: invalid base64 in {label}"
        ) from err


def _hmac_sha3_512(key: bytes, message: str | bytes) -> bytes:
    data = message.encode("utf-8") if isinstance(message, str) else message
    return hmac.new(key, data, hashlib.sha3_512).digest()


def _proof(client_key: bytes, stored_key: bytes, message: str) -> str:
    client_signature = _hmac_sha3_512(stored_key, message)
    if len(client_key) != len(client_signature):
        raise InteractiveAuthError("NDW4: proof length mismatch")

    mixed = bytes(a ^ b for a, b in zip(client_key, client_signature))
    return base64.b64encode(mixed).decode("ascii")


async def _post(
    session: aiohttp.ClientSession,
    url: str,
    payload: dict[str, Any],
    cookie: str | None,
    timeout: int,
) -> tuple[aiohttp.ClientResponse, str | None]:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie

    try:
        async with asyncio.timeout(timeout):
            response = await session.post(
                url,
                json=payload,
                headers=headers,
                allow_redirects=False,
            )
            # Materialise the response before returning it. Headers remain
            # available after the connection is released back to the pool.
            await response.read()
    except (aiohttp.ClientError, TimeoutError) as err:
        raise InteractiveAuthError(
            f"Interactive auth POST failed: {err}"
        ) from err

    return response, _extract_cookie(response) or cookie


async def _get(
    session: aiohttp.ClientSession,
    url: str,
    timeout: int,
    cookie: str | None = None,
) -> tuple[aiohttp.ClientResponse, str | None]:
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    try:
        async with asyncio.timeout(timeout):
            response = await session.get(
                url,
                headers=headers,
                allow_redirects=False,
            )
            await response.read()
    except (aiohttp.ClientError, TimeoutError) as err:
        raise InteractiveAuthError(
            f"Interactive auth GET failed: {err}"
        ) from err

    return response, _extract_cookie(response) or cookie


async def _authenticate_ndw4(
    *,
    session: aiohttp.ClientSession,
    base_url: str,
    endpoint: str,
    username: str,
    password: str,
    cookie: str | None,
    timeout: int,
    logger: Any = None,
) -> tuple[dict[str, str], str]:
    """Perform the three-phase NDW4 handshake."""
    auth_url = f"{base_url}{endpoint}"
    client_nonce = base64.b64encode(secrets.token_bytes(16)).decode("ascii")

    # Phase 1: request Argon2 parameters and the combined nonce.
    response1, cookie = await _post(
        session,
        auth_url,
        {"login": username, "nonce": client_nonce},
        cookie,
        timeout,
    )
    reply1 = _decode_reply_header(response1, "phase 1")

    salt_b64 = _require_text(reply1, "salt", "phase 1")
    combined_nonce = _require_text(reply1, "nonce", "phase 1")
    if not combined_nonce.startswith(client_nonce):
        raise InteractiveAuthError("NDW4 phase 1: server nonce mismatch")

    salt = _b64decode(salt_b64, "salt")
    if len(salt) != 16:
        raise InteractiveAuthError("NDW4 phase 1: salt must be 16 bytes")

    iter_raw, iterations = _cost(reply1.get("iter"), "iter", 1, 64)
    mem_raw, memory_kib = _cost(
        reply1.get("memcost"),
        "memcost",
        8,
        262144,
    )

    # iter/memcost must be signed exactly as the router returned them.
    auth_message = (
        f"login1={username},nonce1={client_nonce};"
        f"iter2={iter_raw},memcost2={mem_raw},"
        f"nonce2={combined_nonce},salt2={salt_b64};"
        f"login3={username},nonce3={combined_nonce}"
    )

    def _derive() -> tuple[bytes, bytes, bytes]:
        salted_password = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=iterations,
            memory_cost=memory_kib,
            parallelism=1,
            hash_len=64,
            type=Type.ID,
        )
        client_key = _hmac_sha3_512(
            salted_password,
            "NDW4 Interactive Client Key",
        )
        stored_key = hashlib.sha3_512(client_key).digest()
        server_key = _hmac_sha3_512(
            salted_password,
            "NDW4 Interactive Server Key",
        )
        return client_key, stored_key, server_key

    # Argon2 can be expensive; do not block Home Assistant's event loop.
    client_key, stored_key, server_key = await asyncio.to_thread(_derive)

    # Phase 2: prove knowledge of the password and authenticate the server.
    response2, cookie = await _post(
        session,
        auth_url,
        {
            "login": username,
            "nonce": combined_nonce,
            "proof": _proof(client_key, stored_key, auth_message),
        },
        cookie,
        timeout,
    )
    reply2 = _decode_reply_header(response2, "phase 2")

    signature_b64 = _require_text(reply2, "signature", "phase 2")
    actual_signature = _b64decode(signature_b64, "signature")
    expected_signature = _hmac_sha3_512(server_key, auth_message)
    if not hmac.compare_digest(actual_signature, expected_signature):
        raise InteractiveAuthError("NDW4 phase 2: server signature mismatch")

    # Phase 3: acknowledge the verified server signature.
    signature_message = f"{auth_message};signature4={signature_b64}"
    response3, cookie = await _post(
        session,
        auth_url,
        {
            "login": username,
            "nonce": combined_nonce,
            "signature-proof": _proof(
                client_key,
                stored_key,
                signature_message,
            ),
        },
        cookie,
        timeout,
    )
    if response3.status != 200:
        raise InteractiveAuthError(
            f"NDW4 phase 3 failed: HTTP {response3.status}"
        )

    # Verify the authenticated session explicitly, matching the reference
    # SessionManager behaviour.
    verify, cookie = await _get(
        session,
        f"{base_url}/auth",
        timeout,
        cookie,
    )
    if verify.status != 200:
        raise InteractiveAuthError(
            f"NDW4 verification failed: HTTP {verify.status}"
        )

    if logger:
        logger.debug("NDW4 interactive authentication succeeded")

    return ({"Cookie": cookie} if cookie else {}), "NDW4"


async def _authenticate_ndw2(
    *,
    session: aiohttp.ClientSession,
    base_url: str,
    username: str,
    password: str,
    initial_response: aiohttp.ClientResponse,
    cookie: str | None,
    timeout: int,
    logger: Any = None,
) -> tuple[dict[str, str], str]:
    """Perform legacy NDW2 challenge-response authentication."""
    challenge = initial_response.headers.get("X-NDM-Challenge")
    realm = initial_response.headers.get("X-NDM-Realm", "")
    if not challenge:
        raise InteractiveAuthError(
            "NDW2: router did not return X-NDM-Challenge"
        )

    ha1 = hashlib.md5(
        f"{username}:{realm}:{password}".encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()
    response_hash = hashlib.sha256(
        (challenge + ha1).encode("utf-8")
    ).hexdigest()

    response, cookie = await _post(
        session,
        f"{base_url}/auth",
        {"login": username, "password": response_hash},
        cookie,
        timeout,
    )
    if response.status not in (200, 204):
        raise InteractiveAuthError(
            f"NDW2 rejected: HTTP {response.status}"
        )

    if logger:
        logger.debug("NDW2 interactive authentication succeeded")

    return ({"Cookie": cookie} if cookie else {}), "NDW2"


async def authenticate_interactive(
    *,
    session: aiohttp.ClientSession,
    base_url: str,
    username: str,
    password: str,
    timeout: int,
    logger: Any = None,
) -> tuple[dict[str, str], str]:
    """Authenticate using the strongest interactive scheme advertised.

    NDW4 is preferred when available. If the device also advertises NDW2,
    a failed NDW4 attempt falls back to NDW2 for compatibility with mixed
    firmware generations.

    Returns ``(headers_for_future_rci_requests, selected_scheme)``.
    """
    base_url = base_url.rstrip("/")
    auth_url = f"{base_url}/auth"

    initial, cookie = await _get(session, auth_url, timeout)

    if initial.status == 200:
        return ({"Cookie": cookie} if cookie else {}), "existing-session"
    if initial.status != 401:
        raise InteractiveAuthError(
            f"Interactive auth initial GET failed: HTTP {initial.status}"
        )

    auth_values = _www_auth_values(initial)
    ndw4_endpoint = _find_endpoint(auth_values, _NDW4)
    has_ndw2 = any(_NDW2 in value for value in auth_values)

    if ndw4_endpoint:
        try:
            return await _authenticate_ndw4(
                session=session,
                base_url=base_url,
                endpoint=ndw4_endpoint,
                username=username,
                password=password,
                cookie=cookie,
                timeout=timeout,
                logger=logger,
            )
        except InteractiveAuthError as ndw4_error:
            if not has_ndw2:
                raise
            if logger:
                logger.debug(
                    "NDW4 auth failed (%s); trying NDW2 fallback",
                    ndw4_error,
                )

            # Obtain a fresh challenge/session before switching schemes.
            initial, cookie = await _get(session, auth_url, timeout)
            if initial.status != 401:
                raise InteractiveAuthError(
                    "NDW2 fallback could not obtain a fresh challenge: "
                    f"HTTP {initial.status}"
                ) from ndw4_error

    if has_ndw2:
        return await _authenticate_ndw2(
            session=session,
            base_url=base_url,
            username=username,
            password=password,
            initial_response=initial,
            cookie=cookie,
            timeout=timeout,
            logger=logger,
        )

    raise InteractiveAuthError(
        "Router did not advertise x-ndw4-interactive or "
        "x-ndw2-interactive"
    )
