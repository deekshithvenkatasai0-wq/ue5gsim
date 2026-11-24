"""gNB model: RRC connection setup, NAS relay over N2, and Xn handover."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.network import CoreNetwork
    from ..engine import Simulator
    from ..metrics import Metrics
    from ..ue import UE


@dataclass
class Latency:
    """One-way latencies in seconds."""

    air: float = 0.004
    air_jitter: float = 0.002
    n2: float = 0.002
    xn: float = 0.002
    ho_interruption: float = 0.030


class GNB:
    def __init__(
        self,
        sim: Simulator,
        cell_id: int,
        x: float,
        y: float,
        core: CoreNetwork,
        metrics: Metrics,
        tx_power_dbm: float = 46.0,
        freq_ghz: float = 3.5,
        latency: Latency | None = None,
        air_loss_prob: float = 0.0,
    ):
        self.sim = sim
        self.cell_id = cell_id
        self.x = x
        self.y = y
        self.core = core
        self.metrics = metrics
        self.tx_power_dbm = tx_power_dbm
        self.freq_ghz = freq_ghz
        self.latency = latency or Latency()
        self.air_loss_prob = air_loss_prob
        self.neighbours: dict[int, GNB] = {}
        self.ues: dict[int, UE] = {}  # RRC_CONNECTED UEs keyed by RAN UE id

    @property
    def name(self) -> str:
        return f"gNB-{self.cell_id}"

    # --- air interface helpers -------------------------------------------

    def _air_delay(self) -> float:
        return self.latency.air + self.sim.rng.uniform(0, self.latency.air_jitter)

    def _lost(self) -> bool:
        if self.air_loss_prob and self.sim.rng.random() < self.air_loss_prob:
            self.metrics.inc("air_messages_lost")
            return True
        return False

    def _to_ue(self, fn, *args) -> None:  # noqa: ANN001
        if not self._lost():
            self.sim.schedule(self._air_delay(), fn, *args)

    # --- RRC --------------------------------------------------------------

    def rrc_setup_request(self, ue: UE) -> None:
        self.metrics.log(self.sim.now, self.name, "RRCSetupRequest", ue=ue.ue_id)
        self._to_ue(ue.on_rrc_setup, self)

    def rrc_setup_complete(self, ue: UE, nas_pdu: bytes) -> None:
        self.ues[ue.ue_id] = ue
        self.metrics.log(self.sim.now, self.name, "InitialUEMessage", ue=ue.ue_id)
        self.sim.schedule(self.latency.n2, self.core.initial_ue_message, self, ue.ue_id, nas_pdu)

    def connected_count(self) -> int:
        return len(self.ues)

    # --- NAS relay (N2 / NGAP) ---------------------------------------------

    def uplink_nas(self, ue: UE, nas_pdu: bytes) -> None:
        if ue.ue_id not in self.ues or self._lost():
            return
        delay = self._air_delay() + self.latency.n2
        self.sim.schedule(delay, self.core.uplink_nas, self, ue.ue_id, nas_pdu)

    def downlink_nas(self, ran_ue_id: int, nas_pdu: bytes) -> None:
        ue = self.ues.get(ran_ue_id)
        if ue is None:
            self.metrics.inc("dl_nas_dropped_no_context")
            return
        self._to_ue(ue.on_nas, self, nas_pdu)

    def ue_context_release(self, ran_ue_id: int) -> None:
        ue = self.ues.pop(ran_ue_id, None)
        if ue is not None:
            self.metrics.log(self.sim.now, self.name, "RRCRelease", ue=ran_ue_id)
            self.sim.schedule(self._air_delay(), ue.on_rrc_release, self)

    # --- Mobility (Xn handover) ------------------------------------------

    def measurement_report(self, ue: UE, target_cell_id: int) -> None:
        target = self.neighbours.get(target_cell_id)
        if target is None or ue.ue_id not in self.ues:
            return
        self.metrics.log(self.sim.now, self.name, "HandoverRequest", ue=ue.ue_id, target=target_cell_id)
        self.sim.schedule(self.latency.xn, target.xn_handover_request, self, ue)

    def xn_handover_request(self, source: GNB, ue: UE) -> None:
        self.ues[ue.ue_id] = ue  # admission control always succeeds
        self.sim.schedule(self.latency.xn, source.xn_handover_ack, self, ue)

    def xn_handover_ack(self, target: GNB, ue: UE) -> None:
        if self.ues.pop(ue.ue_id, None) is None:
            target.ues.pop(ue.ue_id, None)
            return
        self.sim.schedule(self._air_delay(), ue.on_handover_command, self, target)

    def rrc_reconfiguration_complete(self, ue: UE) -> None:
        self.metrics.log(self.sim.now, self.name, "PathSwitchRequest", ue=ue.ue_id)
        self.sim.schedule(self.latency.n2, self.core.path_switch, self, ue.ue_id)
