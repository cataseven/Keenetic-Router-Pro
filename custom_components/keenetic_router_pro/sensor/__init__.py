"""Sensors for Keenetic Router Pro."""

from __future__ import annotations

from typing import Optional

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from ..const import DOMAIN, DATA_COORDINATOR, DATA_CLIENT
from ..coordinator import KeeneticCoordinator
from .. import KeeneticClient

from .system import (
    KeeneticCpuLoadSensor,
    KeeneticMemoryUsageSensor,
    KeeneticUptimeSensor,
    KeeneticFirmwareVersionSensor,
)
from .network import (
    KeeneticWanStatusSensor,
    KeeneticWanIpSensor,
    KeeneticPppoeUptimeSensor,
    KeeneticActiveConnectionsSensor,
    KeeneticLocalIpSensor,
)
from .clients import (
    KeeneticConnectedClientsSensor,
    KeeneticRouterClientsSensor,
    KeeneticDisconnectedClientsSensor,
    KeeneticExtenderCountSensor,
)
from .wifi import (
    KeeneticWifi24TemperatureSensor,
    KeeneticWifi5TemperatureSensor,
    KeeneticWifi24RxSensor,
    KeeneticWifi24TxSensor,
    KeeneticWifi5RxSensor,
    KeeneticWifi5TxSensor,
)
from .wireguard import KeeneticWgUptimeSensor, KeeneticWgRxSensor, KeeneticWgTxSensor
from .usb import KeeneticUsbStorageSensor, KeeneticMeshUsbStorageSensor
from .mesh import (
    KeeneticMeshSystemStateSensor,
    KeeneticMeshCpuLoadSensor,
    KeeneticMeshMemorySensor,
    KeeneticMeshUptimeSensor,
    KeeneticMeshClientsSensor,
    KeeneticMeshFirmwareVersionSensor,
    KeeneticMeshLocalIpSensor,
)
from .traffic import (
    KeeneticLanRxSensor,
    KeeneticLanTxSensor,
    KeeneticWanRxSensor,
    KeeneticWanTxSensor,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Keenetic Router Pro sensors from a config entry."""
    data = hass.data[DOMAIN][entry.entry_id]
    coordinator: KeeneticCoordinator = data[DATA_COORDINATOR]
    client: Optional[KeeneticClient] = data.get(DATA_CLIENT)
    entities: list[SensorEntity] = []

    # Системные сенсоры
    entities.append(KeeneticCpuLoadSensor(coordinator, entry))
    entities.append(KeeneticMemoryUsageSensor(coordinator, entry))
    entities.append(KeeneticUptimeSensor(coordinator, entry))
    entities.append(KeeneticFirmwareVersionSensor(coordinator, entry))

    # Сетевые сенсоры
    entities.append(KeeneticWanStatusSensor(coordinator, entry))
    entities.append(KeeneticWanIpSensor(coordinator, entry))
    entities.append(KeeneticPppoeUptimeSensor(coordinator, entry))
    entities.append(KeeneticActiveConnectionsSensor(coordinator, entry))

    # Клиентские сенсоры
    entities.append(KeeneticConnectedClientsSensor(coordinator, entry))
    entities.append(KeeneticRouterClientsSensor(coordinator, entry))
    entities.append(KeeneticDisconnectedClientsSensor(coordinator, entry))
    entities.append(KeeneticExtenderCountSensor(coordinator, entry))

    # WiFi сенсоры
    entities.append(KeeneticWifi24TemperatureSensor(coordinator, entry))
    entities.append(KeeneticWifi5TemperatureSensor(coordinator, entry))
    entities.append(KeeneticWifi24RxSensor(coordinator, entry))
    entities.append(KeeneticWifi24TxSensor(coordinator, entry))
    entities.append(KeeneticWifi5RxSensor(coordinator, entry))
    entities.append(KeeneticWifi5TxSensor(coordinator, entry))

    # Трафик сенсоры
    entities.append(KeeneticLanRxSensor(coordinator, entry))
    entities.append(KeeneticLanTxSensor(coordinator, entry))
    entities.append(KeeneticWanRxSensor(coordinator, entry))
    entities.append(KeeneticWanTxSensor(coordinator, entry))

    # IP сенсоры
    if client:
        entities.append(KeeneticLocalIpSensor(coordinator, entry, client._host))
    else:
        host = entry.data.get("host", "unknown")
        entities.append(KeeneticLocalIpSensor(coordinator, entry, host))

    # Mesh система
    entities.append(KeeneticMeshSystemStateSensor(coordinator, entry))

    # Mesh ноды
    mesh_nodes = coordinator.data.get("mesh_nodes", [])
    for node in mesh_nodes:
        node_cid = node.get("cid") or node.get("id")
        node_ip = node.get("ip")
        if node_cid:
            entities.append(KeeneticMeshCpuLoadSensor(coordinator, entry, node_cid))
            entities.append(KeeneticMeshMemorySensor(coordinator, entry, node_cid))
            entities.append(KeeneticMeshUptimeSensor(coordinator, entry, node_cid))
            entities.append(KeeneticMeshClientsSensor(coordinator, entry, node_cid))
            entities.append(KeeneticMeshFirmwareVersionSensor(coordinator, entry, node_cid))
            if node_ip:
                entities.append(KeeneticMeshLocalIpSensor(coordinator, entry, node_cid, node_ip))

    # WireGuard
    wg_profiles = coordinator.data.get("wireguard", {}).get("profiles", {})
    for name in wg_profiles:
        entities.append(KeeneticWgUptimeSensor(coordinator, entry, name))
        entities.append(KeeneticWgRxSensor(coordinator, entry, name))
        entities.append(KeeneticWgTxSensor(coordinator, entry, name))

    # USB сенсоры (основной роутер)
    usb_devices = coordinator.data.get("usb_storage", [])
    for usb_dev in usb_devices:
        dev_id = usb_dev.get("id")
        if dev_id:
            entities.append(KeeneticUsbStorageSensor(coordinator, entry, dev_id))

    # USB сенсоры (mesh ноды)
    mesh_usb_devices = coordinator.data.get("mesh_usb", [])
    for musb_dev in mesh_usb_devices:
        dev_id = musb_dev.get("id")
        if dev_id:
            entities.append(KeeneticMeshUsbStorageSensor(
                coordinator, entry, dev_id,
                mesh_node_name=musb_dev.get("mesh_node_name"),
                mesh_cid=musb_dev.get("mesh_cid"),
            ))

    async_add_entities(entities)