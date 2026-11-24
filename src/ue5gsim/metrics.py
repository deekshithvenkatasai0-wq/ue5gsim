"""Collection of KPIs and an optional event trace."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    idx = (len(s) - 1) * p / 100.0
    lo = int(idx)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (idx - lo)


@dataclass
class Metrics:
    trace_enabled: bool = False
    counters: Counter = field(default_factory=Counter)
    registration_latency_ms: list[float] = field(default_factory=list)
    pdu_session_latency_ms: list[float] = field(default_factory=list)
    ho_interruption_ms: list[float] = field(default_factory=list)
    sinr_db: list[float] = field(default_factory=list)
    throughput_mbps: list[float] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)

    def inc(self, name: str, n: int = 1) -> None:
        self.counters[name] += n

    def log(self, t: float, who: str, event: str, **details: Any) -> None:
        if self.trace_enabled:
            self.trace.append({"t": round(t, 6), "who": who, "event": event, **details})

    @staticmethod
    def _stats(values: list[float]) -> dict[str, Any]:
        if not values:
            return {"count": 0}
        return {
            "count": len(values),
            "mean": round(sum(values) / len(values), 2),
            "p50": round(percentile(values, 50), 2),
            "p95": round(percentile(values, 95), 2),
            "max": round(max(values), 2),
        }

    def summary(self) -> dict[str, Any]:
        attempts = self.counters["registration_attempts"]
        success = self.counters["registration_success"]
        return {
            "counters": dict(sorted(self.counters.items())),
            "registration_success_rate": round(success / attempts, 4) if attempts else None,
            "registration_latency_ms": self._stats(self.registration_latency_ms),
            "pdu_session_latency_ms": self._stats(self.pdu_session_latency_ms),
            "handover_interruption_ms": self._stats(self.ho_interruption_ms),
            "sinr_db": self._stats(self.sinr_db),
            "throughput_mbps": self._stats(self.throughput_mbps),
        }
