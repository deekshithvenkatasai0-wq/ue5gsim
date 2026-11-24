"""Radio propagation and link abstraction.

* Path loss: 3GPP TR 38.901 UMa LOS (single-slope form, valid up to the breakpoint).
* Shadow fading: log-normal, spatially correlated per UE/cell with a
  Gudmundson exponential model.
* Link quality: SINR -> CQI (TS 38.214 Table 5.2.2.1-3 style thresholds) and
  a capped, overhead-adjusted Shannon throughput.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from .gnb import GNB

# Approximate SINR (dB) needed for 10% BLER at CQI 1..15 (256QAM table).
CQI_SINR_THRESHOLDS_DB = (
    -6.7, -4.7, -2.3, 0.2, 2.4, 4.3, 5.9, 8.1, 10.3, 11.7, 14.1, 16.3, 18.7, 21.0, 22.7,
)
MAX_SPECTRAL_EFFICIENCY = 7.4063  # bits/s/Hz, CQI 15 of 256QAM table
OVERHEAD_FACTOR = 0.75  # control channels, reference signals, guard bands


class Positioned(Protocol):
    ue_id: int
    x: float
    y: float


def dbm_to_mw(dbm: float) -> float:
    return 10 ** (dbm / 10.0)


def mw_to_dbm(mw: float) -> float:
    return 10.0 * math.log10(max(mw, 1e-30))


def pathloss_uma_los(d2d_m: float, fc_ghz: float, h_bs: float = 25.0, h_ut: float = 1.5) -> float:
    d3d = math.hypot(max(d2d_m, 10.0), h_bs - h_ut)
    return 28.0 + 22.0 * math.log10(d3d) + 20.0 * math.log10(fc_ghz)


def sinr_to_cqi(sinr_db: float) -> int:
    cqi = 0
    for i, threshold in enumerate(CQI_SINR_THRESHOLDS_DB, start=1):
        if sinr_db >= threshold:
            cqi = i
    return cqi


@dataclass
class CarrierConfig:
    bandwidth_hz: float = 20e6
    scs_hz: float = 30e3
    num_prb: int = 51
    noise_figure_db: float = 7.0

    @property
    def noise_per_re_dbm(self) -> float:
        return -174.0 + 10 * math.log10(self.scs_hz) + self.noise_figure_db


class RadioEnvironment:
    def __init__(
        self,
        rng: random.Random,
        carrier: CarrierConfig | None = None,
        shadow_std_db: float = 4.0,
        decorrelation_m: float = 37.0,
    ):
        self.rng = rng
        self.carrier = carrier or CarrierConfig()
        self.shadow_std_db = shadow_std_db
        self.decorrelation_m = decorrelation_m
        self.cells: list[GNB] = []
        # (ue_id, cell_id) -> (shadow_db, x, y) at last update
        self._shadow: dict[tuple[int, int], tuple[float, float, float]] = {}

    def add_cell(self, cell: GNB) -> None:
        self.cells.append(cell)

    def _shadowing(self, ue: Positioned, cell: GNB) -> float:
        key = (ue.ue_id, cell.cell_id)
        prev = self._shadow.get(key)
        if prev is None:
            value = self.rng.gauss(0.0, self.shadow_std_db)
        else:
            old, px, py = prev
            rho = math.exp(-math.hypot(ue.x - px, ue.y - py) / self.decorrelation_m)
            value = rho * old + math.sqrt(1 - rho * rho) * self.rng.gauss(0.0, self.shadow_std_db)
        self._shadow[key] = (value, ue.x, ue.y)
        return value

    def rx_power_per_re_dbm(self, ue: Positioned, cell: GNB) -> float:
        """RSRP-like received power per resource element."""
        tx_per_re = cell.tx_power_dbm - 10 * math.log10(12 * self.carrier.num_prb)
        d = math.hypot(ue.x - cell.x, ue.y - cell.y)
        return tx_per_re - pathloss_uma_los(d, cell.freq_ghz) - self._shadowing(ue, cell)

    def measure(self, ue: Positioned) -> dict[int, float]:
        return {c.cell_id: self.rx_power_per_re_dbm(ue, c) for c in self.cells}

    def sinr_db(self, rsrp_by_cell: dict[int, float], serving_cell_id: int) -> float:
        signal = dbm_to_mw(rsrp_by_cell[serving_cell_id])
        interference = sum(dbm_to_mw(p) for cid, p in rsrp_by_cell.items() if cid != serving_cell_id)
        noise = dbm_to_mw(self.carrier.noise_per_re_dbm)
        return mw_to_dbm(signal) - mw_to_dbm(interference + noise)

    def throughput_mbps(self, sinr_db: float, share: int = 1) -> float:
        se = min(math.log2(1 + 10 ** (sinr_db / 10)), MAX_SPECTRAL_EFFICIENCY)
        if sinr_to_cqi(sinr_db) == 0:
            se = 0.0
        return self.carrier.bandwidth_hz * se * OVERHEAD_FACTOR / max(share, 1) / 1e6
