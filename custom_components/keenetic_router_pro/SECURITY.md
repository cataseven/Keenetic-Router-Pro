# Security Policy

This document describes the security model and trust boundaries of the
Keenetic Router Pro Home Assistant integration, what the integration
itself protects, and — honestly — what it cannot protect on your
behalf.

## Reporting a vulnerability

Please open a **private** security advisory on GitHub
(`Security → Advisories → New draft advisory`) rather than a public
issue. Include enough detail to reproduce the problem, the affected
version (`manifest.json` → `version`), and the impact you observed.

A public issue with proof-of-concept code, screenshots of credentials,
or diagnostics dumps is itself a leak — please don't.

## What this integration protects

The integration tries hard to keep your router credentials and network
fingerprint out of any output a user is likely to share publicly.

### Diagnostics download

The "Download Diagnostics" button on the integration's config-entry
card (`Settings → Devices & Services → Keenetic Router Pro → ⋮`)
produces a JSON file that users routinely attach to GitHub issues.
Before that file is written, the payload is passed through Home
Assistant's `async_redact_data` helper. The following key categories
become `**REDACTED**`:

- Credentials: `password`, `username`, `login`, `host`,
  `authorization`, `cookie`, `set-cookie`, `token`,
  `x-ndm-challenge`, `x-ndm-realm`
- Sign-in handshake material (NDW2 / NDW4 / access tokens):
  `www-authenticate`, `x-ndm-data`, `x-ndma-tkn`, `challenge`,
  `session_id`, `session_cookie`, `nonce`, `salt`, `proof`, `signature`
- Network identifiers: `ip`, `ip_address`, `ipv4`, `ipv6`, `mac`,
  `mac_address`, `bssid`, `ssid`, plus the keys Keenetic uses for
  addresses (`address`, `gateway`, `remote`, `remote_peer`,
  `local_endpoint`, `remote_endpoint`, `local-endpoint-address`,
  `remote-endpoint-address`, `ac-mac`)
- Wi-Fi PSKs / keys: `psk`, `passphrase`, `pre_shared_key`, `key`,
  `secret`
- Hardware fingerprints: `serial`, `serial_number`, `hw_id`, `hwid`,
  `device_id`, `uuid`
- DDNS / KeenDNS hostnames: `domain`, `fqdn`

Matching is exact and case-sensitive, so every spelling a payload uses
has to be listed.

Coordinator indexes whose **keys** are MAC addresses (`host_policies`,
the ping coordinator's MAC→reachability map) are stripped down to a
row count, because `async_redact_data` only scrubs values — without
this dedicated pass the MACs would leak through dict keys even after
redaction. Wi-Fi passwords, which the coordinator stores keyed by
interface rather than under a `psk`-style key, are masked by their own
pass.

### Logs

- `KeeneticClient.__repr__` is hard-coded to never expose
  username/password. A stray `_LOGGER.debug("client=%s", client)` or
  a traceback that includes the client instance can no longer leak
  credentials into `home-assistant.log`.
- Sensitive HTTP headers (`Authorization`, `Cookie`) are not logged
  on RCI requests.
- Sign-in, even at debug level, logs only the schemes the router
  offers, URLs, HTTP status codes and the Argon2 cost and timing. The
  password, the NDW2 hash and challenge, NDW4 proofs, signatures and
  salts, and session cookies are never written. The same goes for
  Wi-Fi passwords fetched from the router.
- **Versions up to and including 1.3.9 did log some of this at debug
  level**: the setup form's input (including the password in plain
  text), the NDW2 challenge and response hash, raw sign-in headers
  and the session cookie. If you shared a debug log from one of those
  versions, rotate the router password.

### Command injection

Every value that ends up interpolated into a Keenetic `/rci/parse`
CLI command (interface names, MAC addresses, crypto-map names, mesh
component IDs, policy IDs, ping targets) is validated through
`_validate_cli_arg` against a strict allow-list. The router executes
the parsed command as a CLI line, so an unvalidated value containing
whitespace + a second CLI command would otherwise run that command
too. The allow-list accepts only `[A-Za-z0-9_.:/\-]` — the legitimate
character set on this firmware family.

### Config-flow input

The router password field uses Home Assistant's password selector,
which renders as dots in the UI on every config-flow step (initial
setup, SSDP-discovered confirm, the future re-auth / reconfigure
flow). This prevents shoulder-surfing and accidental screenshot
leaks during setup.

## What this integration **cannot** protect

Home Assistant stores every config entry's `data` field — including
your Keenetic admin password — as **plaintext JSON** in
`<config>/.storage/core.config_entries`. This is a property of how
Home Assistant stores integration credentials in general, and no
integration can fix it.

Practical implications:

- **Anyone with read access to your HA config directory can recover
  your router password.** That includes anyone who can read a HA
  backup, snapshot, or `.storage/` dump.
- If you have ever published, shared, or attached a HA backup, snapshot,
  or `core.config_entries` file publicly (a GitHub issue, a Discord
  paste, a debug bundle on a forum), **assume your router password
  is compromised** and rotate it.
- If you use plaintext HTTP (`SSL = false`) and your router is not on
  loopback (`127.0.0.1` / `localhost`), your router username, Basic
  Auth header or sign-in handshake (NDW2 response, NDW4 proof), and
  session cookie traverse the LAN unencrypted on every coordinator
  poll (every 10 seconds by default). Anyone on the same broadcast
  domain can capture them.

### Recommended hygiene

- **Use HTTPS / TLS** between Home Assistant and the router whenever
  possible. Even self-signed certificates are better than plaintext
  HTTP for LAN traffic.
- Restrict the file permissions of `<config>/.storage/`:
  `chmod 600 <config>/.storage/core.config_entries`. This won't help
  against a user with root or the `homeassistant` user, but it does
  reduce the blast radius of misconfigured backups.
- **Rotate the router admin password** after sharing any HA
  diagnostics, backup, or config snapshot — even if you ran it
  through this integration's redactor, treat the rotation as a
  cheap insurance policy.
- Don't run Home Assistant debug logging persistently. If you turn it
  on for troubleshooting, turn it off afterward and consider
  rotating the password if debug logs were collected at the time
  the integration first authenticated.
- Avoid posting the output of `curl -v https://router/...` publicly
  — `-v` prints the Authorization header. If you've shared that,
  rotate the password.

## What changed recently

See [`CHANGELOG.md`](CHANGELOG.md) for the per-release security
history. Security-related changes are flagged with 🔒 in the changelog
entries.
