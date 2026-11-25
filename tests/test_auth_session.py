"""Regression tests for Keenetic HTTP session handling."""

from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import Mock, patch

from aiohttp import ClientSession, web

from custom_components.keenetic_router_pro import async_get_router_session
from custom_components.keenetic_router_pro.api import KeeneticClient


class AuthSessionTest(IsolatedAsyncioTestCase):
    async def test_new_client_does_not_replay_previous_clients_cookie(self):
        """The config flow and entry setup must each get a fresh challenge."""
        challenges = 0

        async def get_auth(request):
            nonlocal challenges
            if request.cookies.get("router_session", "").startswith("signed-in-"):
                return web.json_response({"method": "x-ndw2-interactive"})

            challenges += 1
            response = web.Response(
                status=401,
                headers={"X-NDM-Challenge": "test-challenge", "X-NDM-Realm": "test"},
            )
            response.set_cookie("router_session", f"challenge-{challenges}")
            return response

        async def post_auth(request):
            if request.cookies.get("router_session") != f"challenge-{challenges}":
                return web.Response(status=401)
            response = web.Response()
            response.set_cookie("router_session", f"signed-in-{challenges}")
            return response

        async def get_system(request):
            if request.cookies.get("router_session") != f"signed-in-{challenges}":
                return web.Response(status=401)
            return web.json_response({"hostname": "test-router"})

        app = web.Application()
        app.router.add_get("/auth", get_auth)
        app.router.add_post("/auth", post_auth)
        app.router.add_get("/rci/show/system", get_system)
        runner = web.AppRunner(app)
        await runner.setup()
        self.addAsyncCleanup(runner.cleanup)
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = runner.addresses[0][1]
        hass = SimpleNamespace(data={}, bus=Mock())

        def create_session(_hass, *, auto_cleanup, cookie_jar):
            self.assertFalse(auto_cleanup)
            session = ClientSession(cookie_jar=cookie_jar)
            self.addAsyncCleanup(session.close)
            return session

        with patch(
            "custom_components.keenetic_router_pro.async_create_clientsession",
            side_effect=create_session,
        ) as create:
            for _ in range(2):
                client = KeeneticClient(
                    host="localhost",
                    port=port,
                    username="test-user",
                    password="test-password",
                    use_challenge_auth=True,
                )
                await client.async_start(async_get_router_session(hass))
                self.assertEqual(
                    await client.async_get_system_info(), {"hostname": "test-router"}
                )

        self.assertEqual(challenges, 2)
        create.assert_called_once()
        hass.bus.async_listen_once.assert_called_once()
