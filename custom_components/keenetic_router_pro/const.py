"""Constants for the Keenetic Router Pro integration."""

DOMAIN = "keenetic_router_pro"
DEFAULT_PORT = 100
DEFAULT_SSL = False
FAST_SCAN_INTERVAL = 10
SLOW_SCAN_INTERVAL = 60

# --- Cloud KeenDNS hardening (issue #43 follow-up) --------------------
# When a router is reached through KeenDNS *cloud* mode
# (``*.keenetic.pro`` / ``.link`` / ``.io`` / ``.name`` or any remote
# HTTPS host), every RCI call traverses Keenetic's hosted reverse
# proxy. That proxy enforces strict per-source rate / payload limits
# and treats a sudden burst from one WAN IP as a brute-force flood —
# invalidating the auth cookie on EVERY cloud site behind that IP at
# once. A single coordinator tick fires 25-40 RCI calls, and on HA
# restart every configured router fires its first tick simultaneously,
# so the proxy sees one massive spike and drops all sessions, which the
# user then has to clear by reconfiguring each entry. These constants
# tame the burst without changing anything for direct-to-LAN setups.
#
# * Slower poll so the steady-state request rate stays under the proxy
#   limit (LAN keeps the snappy 10 s interval).
CLOUD_SCAN_INTERVAL = 30
# * At most N in-flight RCI calls per cloud router. LOCAL value is pure
#   headroom (the coordinator already caps its own fan-out at 4) so
#   direct-LAN behaviour is byte-for-byte unchanged.
CLOUD_MAX_CONCURRENCY = 2
LOCAL_MAX_CONCURRENCY = 8
# * Minimum spacing between two cloud RCI calls. Converts a 25-call
#   burst into a ~3-5 s smooth trickle that the flood detector ignores.
CLOUD_MIN_REQUEST_INTERVAL = 0.2
# * First-poll spread on startup so N routers don't all hit the proxy
#   at t=0. Scaled by the number of *sibling* cloud entries: a lone
#   cloud router waits ~0 s (its own pacing is enough), while a fleet
#   of 10 spreads its first polls across up to ~36 s.
CLOUD_STARTUP_JITTER_PER_ENTRY = 4.0
CLOUD_STARTUP_JITTER_CAP = 45.0
# Hostnames whose suffix unambiguously means KeenDNS cloud mode.
KEENDNS_CLOUD_SUFFIXES = (
    ".keenetic.pro",
    ".keenetic.link",
    ".keenetic.io",
    ".keenetic.name",
)
# Local-only TLDs / suffixes that must never be treated as cloud even
# when reached over HTTPS (mDNS and common home-LAN search domains).
LOCAL_HOST_SUFFIXES = (
    ".local",
    ".lan",
    ".home",
    ".internal",
    ".localdomain",
)
PING_SCAN_INTERVAL = 3  # legacy default, kept for backwards compatibility
DEFAULT_PING_INTERVAL = 5
MIN_PING_INTERVAL = 5
MAX_PING_INTERVAL = 300
CONF_PING_INTERVAL = "ping_interval"
DATA_CLIENT = "client"
DATA_COORDINATOR = "coordinator"
DATA_PING_COORDINATOR = "ping_coordinator"
CONF_TRACKED_CLIENTS = "tracked_clients"
CONF_USE_CHALLENGE_AUTH = "use_challenge_auth"
EVENT_NEW_DEVICE = f"{DOMAIN}_new_device"
COORD_RC_INTERFACE = "coord_rc_interface"

# Sprint 7 / issue #48: device-tracker fallback to router-reported link
# state when ICMP ping fails. Catches the cross-subnet scenario where
# tracked devices are reachable to the router (link=up) but unreachable
# to HA's ICMP probe due to firewall rules or routed sub-LANs. Default
# OFF so the feature is strictly opt-in — most home users sit on a flat
# LAN where ICMP is reliable and the router-state fallback would only
# introduce small false-positive windows during disconnect (router takes
# a few seconds to flip link=down on real disconnects). Users who
# actually have cross-subnet devices can enable this in the initial
# setup form OR later via Options.
CONF_LINK_STATE_FALLBACK = "link_state_fallback"
DEFAULT_LINK_STATE_FALLBACK = False
