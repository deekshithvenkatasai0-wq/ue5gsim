"""A small deterministic discrete-event simulation kernel."""

from __future__ import annotations

import heapq
import itertools
import random
from collections.abc import Callable
from typing import Any


class Timer:
    """Handle for a scheduled event that can be cancelled."""

    __slots__ = ("cancelled",)

    def __init__(self) -> None:
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


class Simulator:
    """Event scheduler with a simulated clock (seconds) and a seeded RNG."""

    def __init__(self, seed: int = 0):
        self.now = 0.0
        self.rng = random.Random(seed)
        self._queue: list[tuple[float, int, Timer, Callable[..., Any], tuple[Any, ...]]] = []
        self._seq = itertools.count()
        self.events_processed = 0

    def schedule(self, delay: float, fn: Callable[..., Any], *args: Any) -> Timer:
        if delay < 0:
            raise ValueError("cannot schedule in the past")
        timer = Timer()
        heapq.heappush(self._queue, (self.now + delay, next(self._seq), timer, fn, args))
        return timer

    def run(self, until: float | None = None) -> None:
        while self._queue:
            t, _, timer, fn, args = self._queue[0]
            if until is not None and t > until:
                break
            heapq.heappop(self._queue)
            if timer.cancelled:
                continue
            self.now = t
            self.events_processed += 1
            fn(*args)
        if until is not None:
            self.now = max(self.now, until)
