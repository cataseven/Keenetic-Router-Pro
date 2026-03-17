"""Constants for the Keenetic Router Pro integration."""

DOMAIN = "keenetic_router_pro"
DEFAULT_PORT = 80

CONF_AUTH_TYPE = "auth_type"
AUTH_TYPE_NDMS2 = "ndms2"
AUTH_TYPE_BASIC = "basic"
DEFAULT_AUTH_TYPE = AUTH_TYPE_NDMS2
DEFAULT_SSL = False
FAST_SCAN_INTERVAL = 10
SLOW_SCAN_INTERVAL = 60
PING_SCAN_INTERVAL = 3
DATA_CLIENT = "client"
DATA_COORDINATOR = "coordinator"
DATA_PING_COORDINATOR = "ping_coordinator"
CONF_TRACKED_CLIENTS = "tracked_clients"
EVENT_NEW_DEVICE = f"{DOMAIN}_new_device"
