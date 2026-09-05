"""Keenetic client with modern interactive authentication support."""
from __future__ import annotations

import logging

from .api import KeeneticAuthError, KeeneticClient as BaseKeeneticClient
from .const import DOMAIN
from .ndw4_auth import InteractiveAuthError, authenticate_interactive

_LOGGER = logging.getLogger(f"custom_components.{DOMAIN}.api")


class KeeneticClient(BaseKeeneticClient):
    """Extend the existing API client with NDW4/NDW2 interactive auth.

    The public constructor and all RCI methods are inherited unchanged. The
    existing ``use_challenge_auth`` config flag now means "interactive auth":
    NDW4 is preferred when advertised, with NDW2 retained as a fallback.
    """

    async def _async_authenticate_challenge(self) -> None:
        """Authenticate interactively, preferring NDW4 over NDW2."""
        if self._session is None:
            raise KeeneticAuthError("ClientSession is not set")

        try:
            auth_header, scheme = await authenticate_interactive(
                session=self._session,
                base_url=self._base,
                username=self._username,
                password=self._password,
                timeout=self._request_timeout,
                logger=_LOGGER,
            )
        except InteractiveAuthError as err:
            raise KeeneticAuthError(str(err)) from err

        self._auth_header = auth_header
        self._authenticated = True
        _LOGGER.debug(
            "Authenticated to Keenetic/Netcraze router at %s:%s using %s",
            self._host,
            self._port,
            scheme,
        )
