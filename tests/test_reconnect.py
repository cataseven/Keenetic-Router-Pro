"""Exercise router reconnects with Home Assistant polling and update entities."""

import asyncio
import logging
import tempfile
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import aiohttp
from homeassistant.config_entries import ConfigEntries
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry, entity_registry, frame
from homeassistant.helpers.entity_platform import EntityPlatform

from custom_components.keenetic_router_pro.api import KeeneticClient
from custom_components.keenetic_router_pro.coordinator import KeeneticCoordinator
from custom_components.keenetic_router_pro.update import KeeneticMeshFirmwareUpdate

OLD = "5.2 Beta 2"
NEW = "5.2 Beta 3"
NODE = "fixture-node"


class RouterResponse:
    def __init__(self, status, payload=None):
        self.status = status
        self.payload = payload
        self.headers = {"content-type": "application/json"}

    async def text(self):
        return ""

    async def json(self):
        return self.payload


class RouterSession:
    def __init__(self):
        self.online = True
        self.authenticated = True
        self.unauthorized = 0
        self.two_requests = asyncio.Event()
        self.firmware = OLD

    async def request(self, method, url, **kwargs):
        if not self.online:
            raise aiohttp.ClientConnectionError("Simulated network outage")
        if not self.authenticated:
            self.unauthorized += 1
            if self.unauthorized == 2:
                self.two_requests.set()
            await self.two_requests.wait()
            return RouterResponse(401)
        if url.endswith("/rci/show/version"):
            return RouterResponse(200, {"title": NEW})
        if url.endswith("/rci/show/mws/member"):
            return RouterResponse(200, [{
                "cid": NODE,
                "model": "Giga",
                "internet-available": True,
                "fw": self.firmware,
                "fw-available": NEW,
            }])
        return RouterResponse(200, {})


async def wait_for_state(hass, entity_id, expected):
    try:
        async with asyncio.timeout(6):
            while (state := hass.states.get(entity_id)) is None or state.state != expected:
                await asyncio.sleep(0.02)
    except TimeoutError as error:
        state = hass.states.get(entity_id)
        raise AssertionError(f"Expected {expected}, got {state}") from error
    return state


async def check(config_dir):
    hass = HomeAssistant(config_dir)
    frame.async_setup(hass)
    hass.config_entries = ConfigEntries(hass, {})
    await hass.config_entries.async_initialize()
    device_registry.async_setup(hass)
    await device_registry.async_load(hass)
    await entity_registry.async_load(hass)
    router = RouterSession()
    client = KeeneticClient(host="router.keenetic.pro", username="fixture",
                           password="fixture", ssl=True, use_challenge_auth=True)
    assert client.cloud_mode
    client._min_request_interval = 0
    client._get_mesh_nodes_from_clients = AsyncMock(return_value=[{"cid": NODE}])

    async def login():
        router.authenticated = client._authenticated = True

    client._async_authenticate_challenge = AsyncMock(side_effect=login)
    await client.async_start(router)
    coordinator = KeeneticCoordinator(hass, client)
    coordinator.update_interval = timedelta(seconds=1)
    entry = SimpleNamespace(entry_id="fixture", title="Fixture")
    entity = KeeneticMeshFirmwareUpdate(coordinator, entry, NODE, client)
    platform = EntityPlatform(
        hass=hass, logger=logging.getLogger(__name__), domain="update",
        platform_name="keenetic_router_pro", platform=None,
        scan_interval=timedelta(seconds=30), entity_namespace=None,
    )

    await hass.async_start()
    try:
        await coordinator.async_refresh()
        with patch.object(KeeneticMeshFirmwareUpdate, "device_info", None):
            await platform.async_add_entities([entity])
        entity_id = entity.entity_id
        assert entity_id is not None
        initial = await wait_for_state(hass, entity_id, "on")
        assert initial.attributes["installed_version"] == OLD
        assert initial.attributes["latest_version"] == NEW

        # Publish an ordinary successful poll before the connection fails.
        polled = asyncio.Event()
        unsubscribe = coordinator.async_add_listener(polled.set)
        try:
            await asyncio.wait_for(polled.wait(), timeout=6)
        finally:
            unsubscribe()

        router.online = False
        await wait_for_state(hass, entity_id, "unavailable")
        assert not coordinator.last_update_success

        # Both requests receive 401, and the mesh data stays the same after login.
        router.authenticated = False
        router.online = True
        await wait_for_state(hass, entity_id, "on")
        assert router.unauthorized == 2
        assert client._async_authenticate_challenge.await_count == 2
        assert coordinator.last_update_success

        # The node upgrades during the outage. The scheduled poll clears the update.
        router.online = False
        await wait_for_state(hass, entity_id, "unavailable")
        router.firmware = NEW
        router.online = True
        updated = await wait_for_state(hass, entity_id, "off")
        assert updated.attributes["installed_version"] == updated.attributes["latest_version"] == NEW
        assert coordinator.last_update_success
    finally:
        await platform.async_reset()
        await hass.async_stop()


class TestKeeneticReconnect(unittest.IsolatedAsyncioTestCase):
    async def test_mesh_update_recovers_after_outage_and_expired_session(self):
        with tempfile.TemporaryDirectory() as config_dir:
            await check(config_dir)
