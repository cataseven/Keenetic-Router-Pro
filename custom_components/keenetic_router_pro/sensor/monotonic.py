"""Monotonic clamping for TOTAL_INCREASING uptime sensors.

Issue #60: the router occasionally reports a *slightly* lower uptime
than the previous poll for Wi-Fi clients (e.g. 3227 -> 3095, a ~4%
dip). A genuine re-association resets the counter to ~0, which the
recorder handles as a meter reset — but a small dip lands in the
recorder's "not strictly increasing" warning band and spams the HA
core log:

    Entity sensor.x_uptime ... has state class total_increasing, but
    its state is not strictly increasing. Triggered by state 3095
    (previous state: 3227.0) ...

HA core's reset detection (homeassistant.components.sensor.recorder
.reset_detected) works like this:

* ``new < 0.9 * previous``            -> legitimate counter reset
* ``0.9 * previous <= new < previous`` -> warning (the dip band)

The likely router-side causes (roaming between mesh members, hotspot
re-basing the session counter after a power-save blip, two competing
association counters) can't be fixed from our side and the dip always
self-heals: uptime keeps ticking, so the raw value overtakes the held
value within ``offset`` seconds.

So instead of changing the state class (which would discard the
"collapse each session into one increasing curve" statistics rationale
documented on KeeneticUptimeSensor) we hold the high-water mark across
dips that fall inside the recorder's warning band, and pass genuine
resets through untouched. The published series is then *guaranteed* to
satisfy the TOTAL_INCREASING contract: it either increases or resets
below the 0.9 threshold.

The mixin also restores the last published value across HA restarts
(RestoreSensor), because the recorder's "previous state" survives
restarts too — without restoring, a dip that straddles a restart would
still warn once.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from homeassistant.components.sensor import RestoreSensor

_LOGGER = logging.getLogger(__name__)

# Mirror of the factor HA's recorder uses in ``reset_detected``. Keep
# in sync conceptually: dips at or above this fraction of the previous
# value are "jitter" (would warn), below it is a real reset.
_RESET_FACTOR = 0.9


def _as_float(value: Any) -> Optional[float]:
    """Best-effort float conversion, returning None on failure."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    # NaN != NaN; comparisons against NaN are always False and would
    # silently corrupt the high-water mark.
    if f != f:
        return None
    return f


class MonotonicUptimeMixin(RestoreSensor):
    """Hold the high-water mark across small uptime dips.

    Subclasses keep their own value extraction and route the result
    through :meth:`_clamp_monotonic` inside ``native_value``::

        @property
        def native_value(self) -> int | None:
            ...
            return self._clamp_monotonic(safe_int(uptime))

    Behaviour:

    * value increased (or unchanged)        -> publish, remember it
    * dip inside the recorder warning band  -> publish the held value
      (the raw counter keeps ticking, so it overtakes the held value
      within ``dip`` seconds and publishing resumes from raw)
    * dip below ``0.9 * held``              -> genuine reset; publish
      the low value so the recorder records a clean meter reset
    """

    # Last value actually published, kept in its native type so the
    # held state doesn't flip between "3227" and "3227.0".
    _monotonic_last_value: Any = None

    async def async_added_to_hass(self) -> None:
        """Seed the high-water mark from the value before restart."""
        await super().async_added_to_hass()
        last_data = await self.async_get_last_sensor_data()
        if last_data is None:
            return
        restored = _as_float(last_data.native_value)
        if restored is not None:
            self._monotonic_last_value = last_data.native_value

    def _clamp_monotonic(self, value: Any) -> Any:
        """Clamp ``value`` so the published series never dips slightly."""
        if value is None:
            return None
        new = _as_float(value)
        if new is None:
            return None

        last = _as_float(self._monotonic_last_value)
        if last is not None and last > new >= last * _RESET_FACTOR:
            # Recorder warning band: hold. Do NOT update the mark, so
            # repeated reads within the same tick stay idempotent and
            # the raw counter can catch up.
            _LOGGER.debug(
                "%s: uptime dipped %.0f -> %.0f (within the recorder's "
                "10%% jitter band, issue #60); holding high-water mark",
                self.entity_id,
                last,
                new,
            )
            return self._monotonic_last_value

        self._monotonic_last_value = value
        return value
