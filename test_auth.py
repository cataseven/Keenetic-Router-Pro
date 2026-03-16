#!/usr/bin/env python3
"""Quick test script for Keenetic NDW2 challenge-response auth.

Tries all known hash variants to find the correct one.
"""

import argparse
import asyncio
import hashlib
import sys

import aiohttp


def compute_variants(username: str, realm: str, password: str, challenge: str) -> list[tuple[str, str]]:
    """Return all plausible (label, hash) variants."""
    md5 = hashlib.md5
    sha = hashlib.sha256

    def h(algo, s: str) -> str:
        return algo(s.encode()).hexdigest()

    p_md5    = h(md5, password)
    p_sha    = h(sha, password)
    urp_md5  = h(md5, f"{username}:{realm}:{password}")
    urp_sha  = h(sha, f"{username}:{realm}:{password}")
    C        = challenge
    C_low    = challenge.lower()

    variants = [
        # --- CORRECT (from Keenetic JS source: sha256(token + md5(u:r:p))) ---
        ("sha256(C + md5(u:r:p))",         h(sha, C + urp_md5)),

        # --- md5-based intermediate ---
        ("sha256(md5(u:r:p) + C)",         h(sha, urp_md5 + C)),
        ("sha256(md5(u:r:p) + ':' + C)",   h(sha, f"{urp_md5}:{C}")),
        ("sha256(md5(pass) + C)",           h(sha, p_md5 + C)),
        ("sha256(md5(pass) + ':' + C)",     h(sha, f"{p_md5}:{C}")),
        ("md5(md5(u:r:p) + C)",            h(md5, urp_md5 + C)),
        ("md5(md5(pass) + C)",              h(md5, p_md5 + C)),

        # --- sha256-based intermediate ---
        ("sha256(sha256(pass) + C)",        h(sha, p_sha + C)),
        ("sha256(sha256(pass) + ':' + C)",  h(sha, f"{p_sha}:{C}")),
        ("sha256(sha256(u:r:p) + C)",       h(sha, urp_sha + C)),
        ("sha256(sha256(u:r:p) + ':' + C)", h(sha, f"{urp_sha}:{C}")),

        # --- reversed order ---
        ("sha256(C + md5(pass))",           h(sha, C + p_md5)),
        ("sha256(C + ':' + md5(pass))",     h(sha, f"{C}:{p_md5}")),
        ("sha256(C + sha256(pass))",        h(sha, C + p_sha)),

        # --- no intermediate hash ---
        ("sha256(pass + C)",                h(sha, password + C)),
        ("sha256(C + pass)",                h(sha, C + password)),
        ("sha256(u + ':' + C + ':' + pass)", h(sha, f"{username}:{C}:{password}")),

        # --- lowercase challenge ---
        ("sha256(md5(pass) + C_lower)",     h(sha, p_md5 + C_low)),
        ("sha256(sha256(pass) + C_lower)",  h(sha, p_sha + C_low)),
        ("sha256(md5(u:r:p) + C_lower)",    h(sha, urp_md5 + C_low)),
    ]
    return variants


async def get_challenge(session: aiohttp.ClientSession, auth_url: str) -> tuple[str, str, str]:
    """GET /auth, return (challenge, realm, session_cookie_kv)."""
    async with session.get(auth_url, allow_redirects=False) as resp:
        print(f"Status : {resp.status}")
        challenge = resp.headers.get("X-NDM-Challenge", "")
        realm     = resp.headers.get("X-NDM-Realm", "")
        raw_cookie = resp.headers.get("Set-Cookie", "")

    if not challenge:
        print("[ERROR] No X-NDM-Challenge header — challenge auth not available on this port.")
        sys.exit(1)

    cookie_kv = ""
    if raw_cookie:
        kv = raw_cookie.split(";")[0].strip()
        if "=" in kv:
            cookie_kv = kv

    print(f"Challenge : {challenge}")
    print(f"Realm     : {realm}")
    print(f"Cookie    : {cookie_kv}")
    return challenge, realm, cookie_kv


async def try_hash(
    session: aiohttp.ClientSession,
    auth_url: str,
    username: str,
    password: str,
    challenge: str,
    realm: str,
    cookie_kv: str,
    label: str,
    response_hash: str,
) -> bool:
    """POST /auth with a single hash variant. Returns True on success."""
    payload = {"login": username, "password": response_hash}
    headers = {"Cookie": cookie_kv} if cookie_kv else {}

    async with session.post(auth_url, json=payload, headers=headers) as resp:
        body = await resp.text()
        ok = resp.status == 200
        mark = "✓ OK" if ok else "✗ 401"
        print(f"  [{mark}]  {label}")
        if ok:
            print(f"          hash = {response_hash}")
        return ok


async def test_rci(session: aiohttp.ClientSession, host: str, port: int, cookie_kv: str) -> None:
    rci_url = f"http://{host}:{port}/rci/show/system"
    headers = {"Cookie": cookie_kv} if cookie_kv else {}
    print(f"\n--- Step 3: GET {rci_url} ---")
    async with session.get(rci_url, headers=headers) as resp:
        print(f"Status : {resp.status}")
        if resp.status == 200:
            data = await resp.json()
            print(f"Hostname: {data.get('hostname', '(not found)')}")
            print("[OK] RCI call works — integration will work!")
        else:
            body = await resp.text()
            print(f"[WARN] {resp.status}: {body!r}")


async def run(host: str, port: int, username: str, password: str) -> None:
    auth_url = f"http://{host}:{port}/auth"
    jar = aiohttp.CookieJar(unsafe=True)

    async with aiohttp.ClientSession(cookie_jar=jar) as session:
        print(f"\n--- Step 1: GET {auth_url} ---")
        challenge, realm, cookie_kv = await get_challenge(session, auth_url)

        variants = compute_variants(username, realm, password, challenge)

        print(f"\n--- Step 2: trying {len(variants)} hash variants ---")
        winning_hash: str | None = None
        winning_label: str | None = None

        for label, h in variants:
            # Each POST needs a fresh challenge because the session is one-time
            # Re-fetch challenge for each attempt
            ch2, realm2, ck2 = await get_challenge(session, auth_url)
            vs = compute_variants(username, realm2, password, ch2)
            # find same label in new variants
            h2 = next(hh for ll, hh in vs if ll == label)

            ok = await try_hash(session, auth_url, username, password, ch2, realm2, ck2, label, h2)
            if ok and winning_hash is None:
                winning_hash = h2
                winning_label = label
                winning_cookie = ck2
                break  # stop at first success

        if winning_hash is None:
            print("\n[FAIL] No variant worked. Check username/password.")
            sys.exit(1)

        print(f"\n[FOUND] Winning algorithm: {winning_label}")
        await test_rci(session, host, port, winning_cookie)


def verify_mode(username: str, realm: str, password: str, challenge: str, expected_hash: str) -> None:
    """Given a known (challenge, expected_hash) pair, find which algorithm matches."""
    print(f"\nVerifying against known hash: {expected_hash}")
    print(f"  username={username!r}  realm={realm!r}  challenge={challenge!r}\n")

    variants = compute_variants(username, realm, password, challenge)
    found = False
    for label, h in variants:
        match = "✓ MATCH" if h == expected_hash else "✗"
        print(f"  [{match}]  {label}")
        print(f"            {h}")
        if h == expected_hash:
            found = True

    if not found:
        print("\n[FAIL] No variant matched — check username/password/challenge/realm.")
    else:
        print("\n[FOUND] Algorithm identified above.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Test Keenetic NDW2 auth variants")
    parser.add_argument("host", nargs="?", help="Router IP, e.g. 192.168.1.1")
    parser.add_argument("--port", type=int, default=80, help="Port (default: 80)")
    parser.add_argument("--username", default="admin", help="Username (default: admin)")
    parser.add_argument("--password", required=True, help="Password")

    # Verify mode: provide known challenge+hash from browser devtools
    parser.add_argument("--challenge", help="Known challenge from GET /auth (verify mode)")
    parser.add_argument("--realm", default="Keenetic Hero", help="Realm (default: 'Keenetic Hero')")
    parser.add_argument("--expected-hash", help="Known hash from POST /auth payload (verify mode)")
    args = parser.parse_args()

    if args.challenge and args.expected_hash:
        verify_mode(args.username, args.realm, args.password, args.challenge, args.expected_hash)
    elif args.host:
        asyncio.run(run(args.host, args.port, args.username, args.password))
    else:
        parser.error("Provide either 'host' or both --challenge and --expected-hash")


if __name__ == "__main__":
    main()
