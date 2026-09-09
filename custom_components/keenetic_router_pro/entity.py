"""Base entity classes for Keenetic Router Pro."""
from typing import Any, Dict, Optional
from homeassistant.core import callback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.device_registry import DeviceInfo
from .const import DOMAIN
from .coordinator import KeeneticCoordinator, KeeneticPingCoordinator
from .utils import (
    get_main_device_info,
    get_mesh_device_info,
    get_client_device_info,
    get_wan_device_info,
    get_crypto_map_device_info,
)


def _entity_fingerprint(
    data: Optional[Dict[str, Any]],
    ignore: frozenset,
) -> Optional[Dict[str, Any]]:
    """Return a dict fingerprint of ``data`` with volatile fields removed.

    The returned dict is what the dedup mixin compares between ticks.
    Fields named in ``ignore`` are excluded so that "only counter
    ticked" updates don't trigger HA state writes; everything else is
    included so semantic changes (link state, IP, role) still fire.
    """
    if not isinstance(data, dict):
        return None
    return {k: v for k, v in data.items() if k not in ignore}


class _FingerprintedCoordinatorEntity(CoordinatorEntity):
    """CoordinatorEntity that suppresses no-op state writes.

    Per-tick coordinator updates push to every listener regardless of
    whether the underlying row actually changed. On a network with
    dozens of tracked clients this means thousands of HA
    ``state_changed`` events per minute, almost all of them no-ops
    that just re-write the recorder with the same value. The
    fingerprint mixin compares a hash-like dict of the "source row"
    each tick and short-circuits the state write when nothing
    semantic moved.

    Subclasses configure two knobs:

    * ``_FINGERPRINT_IGNORE`` — a frozenset of field names whose
      changes are *not* semantic (counters, throughput, timestamps
      that tick every poll). When only these fields move, no write.
    * ``_fingerprint_source`` (property) — returns the current dict
      for "this entity's row" (the client / WAN / mesh-node payload).
      Returning ``None`` opts out of dedup for this tick (e.g. row
      not yet published) — the write proceeds normally.

    Value sensors that *need* per-tick updates because their
    ``native_value`` reads from a field in ``_FINGERPRINT_IGNORE`` (RX
    bytes, throughput, uptime, RSSI, ...) must opt back in by
    overriding ``_FINGERPRINT_IGNORE = frozenset()`` so the fingerprint
    excludes nothing and counter ticks count as changes.
    """

    _FINGERPRINT_IGNORE: frozenset = frozenset()
    _last_fingerprint: Optional[Dict[str, Any]] = None

    @property
    def _fingerprint_source(self) -> Optional[Dict[str, Any]]:
        """Return the dict to fingerprint, or None to bypass dedup."""
        return None

    @property
    def _main_device_id(self) -> Optional[str]:
        """Device registry id of the router this sub-device hangs off.

        Issue #69: sub-devices link to the router by registry id
        (``via_device_id``), not by identifier tuple. ``getattr`` keeps
        this safe against a coordinator built by an older test fixture
        that predates the attribute.
        """
        return getattr(self.coordinator, "main_device_id", None)

    @callback
    def _handle_coordinator_update(self) -> None:
        source = self._fingerprint_source
        # ``source is None`` -> source unknown for this tick (e.g. first
        # tick before coordinator data lands, or row removed from
        # router config). Fall through to the default behaviour so
        # availability transitions still propagate.
        if source is not None:
            fingerprint = _entity_fingerprint(source, self._FINGERPRINT_IGNORE)
            if fingerprint is not None and fingerprint == self._last_fingerprint:
                return
            self._last_fingerprint = fingerprint
        super()._handle_coordinator_update()


class ControllerEntity(CoordinatorEntity):
    """Базовый класс для сущностей главного роутера."""
    
    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry_id: str,
        title: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._title = title
    
    @property
    def _version_data(self) -> Dict[str, Any]:
        """Получить данные версии из /rci/show/version."""
        # Данные из coordinator.data["system"] — это ответ от /rci/show/version
        return self.coordinator.data.get("system", {}) or {}
    
    @property
    def _firmware_version(self) -> Optional[str]:
        """Получить версию прошивки.
        
        Данные приходят из merged system+version в coordinator.data["system"]
        """
        version = self.coordinator.data.get("system", {}) or {}
        
        if version.get("title"):
            return str(version["title"])
        if version.get("release"):
            return str(version["release"])
        
        ndw4 = version.get("ndw4", {})
        if isinstance(ndw4, dict) and ndw4.get("version"):
            return str(ndw4["version"])
        
        return None

    @property
    def _model_name(self) -> Optional[str]:
        """Получить модель роутера.
        
        Приоритет: model > description > device > hw_id
        """
        version = self.coordinator.data.get("system", {}) or {}
        
        if version.get("model"):
            return str(version["model"])
        if version.get("description"):
            return str(version["description"])
        if version.get("device"):
            return str(version["device"])
        if version.get("hw_id"):
            return str(version["hw_id"])
        
        return None
    
    @property
    def device_info(self) -> DeviceInfo:
        ndns_info = self.coordinator.data.get("ndns", {})
        ndns_domain = None
        
        if ndns_info:
            name = ndns_info.get("name")
            domain = ndns_info.get("domain")
            if name and domain:
                ndns_domain = f"{name}.{domain}"
        
        return get_main_device_info(
            self._title, 
            self._entry_id,
            self._firmware_version,
            self._model_name,
            host=getattr(self.coordinator.client, "_host", None),
            ssl=getattr(self.coordinator.client, "_ssl", False),
            ndns_domain=ndns_domain,
        )


class MeshEntity(_FingerprintedCoordinatorEntity):
    """Базовый класс для сущностей Mesh-ноды."""

    # Fields that tick every coordinator update on a healthy mesh node
    # without representing a semantic change. State sensors built on
    # MeshEntity (firmware version, local IP, connected binary) skip
    # the no-op writes; value sensors (CPU, memory, uptime, clients)
    # set _FINGERPRINT_IGNORE = frozenset() to opt back in.
    _FINGERPRINT_IGNORE: frozenset = frozenset({
        "uptime",
        "cpuload",
        "memory",
        "associations",
    })

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry_id: str,
        title: str,
        node_cid: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._title = title
        self._node_cid = node_cid
    
    @property
    def _node(self) -> Optional[Dict[str, Any]]:
        """Get this node's current dict via O(1) index, with linear fallback.

        The coordinator publishes ``mesh_nodes_by_cid`` for fast
        lookup. When the index is absent (older fixture / first tick
        before coordinator data lands) we fall back to a linear scan
        of ``mesh_nodes`` so the entity still works.
        """
        data = self.coordinator.data
        if not data:
            return None
        index = data.get("mesh_nodes_by_cid")
        if isinstance(index, dict):
            # Index exists -> O(1) lookup is authoritative. If the cid
            # is missing the node has been removed from the router
            # config and the entity should report unavailable.
            entry = index.get(self._node_cid)
            return entry if isinstance(entry, dict) else None
        # No index published -> fall back to scanning the list.
        for node in data.get("mesh_nodes", []) or []:
            if (node.get("cid") or node.get("id")) == self._node_cid:
                return node
        return None

    @property
    def _fingerprint_source(self) -> Optional[Dict[str, Any]]:
        return self._node
    
    @property
    def device_info(self) -> DeviceInfo:
        node = self._node
        node_ip = node.get("ip") if node else None
        
        return get_mesh_device_info(
            self._title,
            self._entry_id,
            self._node,
            self._node_cid,
            host=node_ip,
            ssl=getattr(self.coordinator.client, "_ssl", False),
            fqdn=node.get("fqdn") if node else None,
            via_device_id=self._main_device_id,
        )
    
class WanEntity(_FingerprintedCoordinatorEntity):
    """Base class for per-WAN-interface entities.

    Each WAN is exposed in HA as its own sub-device under the main
    router, so all of its sensors (status, IP, uptime, throughput, ...)
    are grouped together in the UI.
    """

    # Counter / throughput / uptime fields tick every coordinator pass
    # on a healthy uplink. State sensors (Public IP, Provider, Role,
    # Interface) deduplicate; value sensors (RX/TX bytes, throughput,
    # uptime) opt out with _FINGERPRINT_IGNORE = frozenset().
    _FINGERPRINT_IGNORE: frozenset = frozenset({
        "rx_bytes",
        "tx_bytes",
        "rx_packets",
        "tx_packets",
        "rx_throughput",
        "tx_throughput",
        "uptime",
        "_sample_ts",
    })

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry_id: str,
        title: str,
        wan_id: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._title = title
        self._wan_id = wan_id

    @property
    def _wan(self) -> Optional[Dict[str, Any]]:
        """Get this WAN's current dict via O(1) index, with linear fallback."""
        data = self.coordinator.data
        if not data:
            return None
        index = data.get("wan_by_id")
        if isinstance(index, dict):
            entry = index.get(self._wan_id)
            return entry if isinstance(entry, dict) else None
        for w in data.get("wan_interfaces", []) or []:
            if w.get("id") == self._wan_id:
                return w
        return None

    @property
    def _fingerprint_source(self) -> Optional[Dict[str, Any]]:
        return self._wan

    @property
    def device_info(self) -> DeviceInfo:
        wan = self._wan or {}
        return get_wan_device_info(
            title=self._title,
            entry_id=self._entry_id,
            wan_id=self._wan_id,
            description=wan.get("description"),
            iface_type=wan.get("type"),
            role_label=wan.get("role_label"),
            via_device_id=self._main_device_id,
        )


class CryptoMapEntity(_FingerprintedCoordinatorEntity):
    """Base class for per-`crypto map` site-to-site IPsec entities.

    Each configured crypto map is exposed in HA as its own sub-device
    under the main router, mirroring the per-WAN model.
    """

    # Crypto map counters tick every poll on an established tunnel.
    # State sensors (Tunnel state, IKE state, Connected) skip no-op
    # writes; RX/TX byte and throughput sensors opt back in with
    # _FINGERPRINT_IGNORE = frozenset().
    _FINGERPRINT_IGNORE: frozenset = frozenset({
        "rx_bytes",
        "tx_bytes",
        "rx_packets",
        "tx_packets",
        "rx_throughput",
        "tx_throughput",
        "phase2_sa_list",   # SA list churns on rekey
        "raw_status",        # full status dict — too noisy to compare
        "_sample_ts",
    })

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry_id: str,
        title: str,
        cmap_name: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._title = title
        self._cmap_name = cmap_name

    @property
    def _cmap(self) -> Optional[Dict[str, Any]]:
        """Return the current dict for this crypto map, or None if it
        has been removed from the router config since we were created."""
        cmaps = self.coordinator.data.get("crypto_maps") or {}
        if not isinstance(cmaps, dict):
            return None
        entry = cmaps.get(self._cmap_name)
        return entry if isinstance(entry, dict) else None

    @property
    def _fingerprint_source(self) -> Optional[Dict[str, Any]]:
        return self._cmap

    @property
    def available(self) -> bool:
        # Mirror CoordinatorEntity.available but additionally require
        # that our tunnel is still present in the router config. If
        # the user deletes the crypto map, our entities become
        # unavailable rather than stale.
        return super().available and self._cmap is not None

    @property
    def device_info(self) -> DeviceInfo:
        cmap = self._cmap or {}
        return get_crypto_map_device_info(
            title=self._title,
            entry_id=self._entry_id,
            cmap_name=self._cmap_name,
            remote_peer=cmap.get("remote_peer"),
            via_device_id=self._main_device_id,
        )


class ClientEntity(_FingerprintedCoordinatorEntity):
    """Базовый класс для сущностей отслеживаемых клиентов как отдельных устройств."""

    # Client rows tick these fields on every coordinator pass even when
    # the device hasn't done anything semantic. State sensors (IP,
    # link, port, connection type, registered, band, mode) deduplicate;
    # value sensors (uptime, last-seen, RX/TX, RSSI, txrate, speed)
    # opt back in with _FINGERPRINT_IGNORE = frozenset().
    _FINGERPRINT_IGNORE: frozenset = frozenset({
        "uptime",
        "last-seen",
        "rxbytes",
        "txbytes",
        "rssi",
        "txrate",
        "speed",        # link speed can flap on healthy WiFi without
                        # representing a real event the user cares about
    })

    def __init__(
        self,
        coordinator: KeeneticCoordinator,
        entry_id: str,
        title: str,
        mac: str,
        label: str,
        initial_ip: Optional[str] = None,
        ping_coordinator = None,  # Optional, for ping tracking
    ) -> None:
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._title = title
        self._mac = mac.lower()
        self._label = label
        self._initial_ip = initial_ip
        self._ping_coordinator = ping_coordinator  # Это должен быть объект, не строка
    
    @property
    def _client(self) -> Optional[Dict[str, Any]]:
        """Get this client's current dict via O(1) MAC index, with linear fallback.

        On a network with hundreds of tracked clients and 15 sensors
        per client this turns an O(N²) per-tick scan into O(N).
        """
        data = self.coordinator.data
        if not data:
            return None
        index = data.get("clients_by_mac")
        if isinstance(index, dict):
            entry = index.get(self._mac)
            return entry if isinstance(entry, dict) else None
        # Fallback: linear scan when index isn't published (test
        # fixtures, partial coord data, pre-1.7 coordinator output).
        for client in data.get("clients", []) or []:
            if str(client.get("mac") or "").lower() == self._mac:
                return client
        return None

    @property
    def _fingerprint_source(self) -> Optional[Dict[str, Any]]:
        return self._client
    
    @property
    def device_info(self) -> DeviceInfo:
        """Device info для отслеживаемого клиента как отдельного устройства."""
        client = self._client
        return get_client_device_info(
            entry_id=self._entry_id,
            mac=self._mac,
            label=self._label,
            client=client,
            initial_ip=self._initial_ip,
            via_device_id=self._main_device_id,
        )
    
    @property
    def ip_address(self) -> Optional[str]:
        """Get current IP address of the client."""
        client = self._client
        if client:
            ip = client.get("ip")
            if ip:
                return str(ip)
        return self._initial_ip
    
    @property
    def hostname(self) -> Optional[str]:
        """Get hostname of the client."""
        client = self._client
        if not client:
            return self._label
        
        name = client.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        h = client.get("hostname")
        if isinstance(h, str) and h.strip():
            return h.strip()
        return self._label
    
    @property
    def _is_apple_device(self) -> bool:
        """Check if this is likely an Apple device."""
        name = self._label or ""
        name_lower = name.lower()
        return any(kw in name_lower for kw in ("apple", "iphone", "ipad", "macbook", "imac"))
    
    @property
    def is_connected(self) -> bool:
        """Determine if device is connected."""
        # Проверяем, что ping_coordinator - это объект, а не строка
        if self._ping_coordinator and hasattr(self._ping_coordinator, 'data') and not self._is_apple_device:
            ping_results = self._ping_coordinator.data or {}
            return ping_results.get(self._mac, False)
        else:
            client = self._client
            if client:
                return str(client.get("link", "")).lower() == "up"
            return False