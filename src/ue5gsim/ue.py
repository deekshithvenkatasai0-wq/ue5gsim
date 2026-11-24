"""The simulated 5G UE: USIM, 5GMM/5GSM NAS state machines, RRC, measurements and mobility."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from .crypto import (
    DOWNLINK,
    UPLINK,
    Milenage,
    NasIntegrityError,
    NasSecurityContext,
    SecHeader,
    derive_kamf,
    derive_kausf,
    derive_kseaf,
    derive_res_star,
    serving_network_name,
    xor,
)
from .nas import EPD_5GSM, MmCause, MmType, NasMessage, SmType, security_header, supi_to_suci

if TYPE_CHECKING:
    from .engine import Simulator, Timer
    from .metrics import Metrics
    from .ran.channel import RadioEnvironment
    from .ran.gnb import GNB


class MmState(Enum):
    """5GMM main states (TS 24.501 5.1.3.2.1.1)."""

    DEREGISTERED = "5GMM-DEREGISTERED"
    REGISTERED_INITIATED = "5GMM-REGISTERED-INITIATED"
    REGISTERED = "5GMM-REGISTERED"
    DEREGISTERED_INITIATED = "5GMM-DEREGISTERED-INITIATED"


class RrcState(Enum):
    IDLE = "RRC_IDLE"
    CONNECTING = "RRC_CONNECTING"
    CONNECTED = "RRC_CONNECTED"


@dataclass
class UsimProfile:
    supi: str
    k: bytes
    opc: bytes
    sqn_ms: int = 0  # highest SQN accepted so far


@dataclass
class UeConfig:
    t3510_s: float = 15.0  # registration guard timer
    max_registration_attempts: int = 5
    measurement_period_s: float = 0.2
    l3_filter_k: int = 4
    a3_offset_db: float = 3.0
    time_to_trigger_s: float = 0.32
    min_rx_level_dbm: float = -125.0
    auto_pdu_session: bool = True
    dnn: str = "internet"
    nea_supported: tuple[int, ...] = (0, 2)
    nia_supported: tuple[int, ...] = (2,)


@dataclass
class Mobility:
    speed_mps: float
    area: tuple[float, float, float, float]  # xmin, ymin, xmax, ymax
    waypoint: tuple[float, float] | None = None
    pause_until: float = 0.0


@dataclass
class PduSession:
    psi: int
    ip: str | None = None
    state: str = "INACTIVE"
    requested_at: float = 0.0


class UE:
    def __init__(
        self,
        sim: Simulator,
        ue_id: int,
        usim: UsimProfile,
        mcc: str,
        mnc: str,
        env: RadioEnvironment,
        metrics: Metrics,
        x: float,
        y: float,
        mobility: Mobility | None = None,
        config: UeConfig | None = None,
    ):
        self.sim = sim
        self.ue_id = ue_id
        self.usim = usim
        self.mcc = mcc
        self.mnc = mnc
        self.sn_name = serving_network_name(mcc, mnc)
        self.env = env
        self.metrics = metrics
        self.x = x
        self.y = y
        self.mobility = mobility
        self.cfg = config or UeConfig()

        self.powered = False
        self.mm = MmState.DEREGISTERED
        self.rrc = RrcState.IDLE
        self.serving: GNB | None = None
        self.sec: NasSecurityContext | None = None
        self.guti: str | None = None
        self.sessions: dict[int, PduSession] = {}
        self.rsrp: dict[int, float] = {}
        self.last_reject_cause: int | None = None

        self._mil = Milenage(usim.k, usim.opc)
        self._pending_kamf: bytes | None = None
        self._t3510: Timer | None = None
        self._reg_attempts = 0
        self._reg_started_at = 0.0
        self._a3: tuple[int, float] | None = None  # (target cell, first seen)
        self._ho_in_progress = False
        self._ho_started_at = 0.0
        self._last_move = 0.0
        self._pti = 0

    @property
    def name(self) -> str:
        return f"UE-{self.ue_id}"

    def _log(self, event: str, **kw) -> None:  # noqa: ANN003
        self.metrics.log(self.sim.now, self.name, event, **kw)

    # ---------------------------------------------------------------- power

    def power_on(self) -> None:
        self.powered = True
        self._last_move = self.sim.now
        self._log("power_on", x=round(self.x, 1), y=round(self.y, 1))
        self._measure()
        self._start_registration()

    def power_off(self) -> None:
        """Switch-off deregistration (no accept expected)."""
        if self.mm == MmState.REGISTERED and self.serving:
            self._send_nas(
                NasMessage(MmType.DEREGISTRATION_REQUEST_UE_ORIG, {"switch_off": True, "access_type": "3gpp", "mobile_identity": self.guti}),
            )
        self.powered = False
        self._enter_deregistered()
        self.rrc = RrcState.IDLE
        self.serving = None
        self._log("power_off")

    def deregister(self) -> None:
        if self.mm != MmState.REGISTERED or self.serving is None:
            return
        self.mm = MmState.DEREGISTERED_INITIATED
        self.metrics.inc("deregistration_attempts")
        self._send_nas(
            NasMessage(MmType.DEREGISTRATION_REQUEST_UE_ORIG, {"switch_off": False, "access_type": "3gpp", "mobile_identity": self.guti}),
        )

    # ------------------------------------------------- cell selection & RRC

    def _best_cell(self) -> GNB | None:
        if not self.rsrp:
            return None
        cid, level = max(self.rsrp.items(), key=lambda kv: kv[1])
        if level < self.cfg.min_rx_level_dbm:
            return None
        return next(c for c in self.env.cells if c.cell_id == cid)

    def _start_registration(self) -> None:
        if not self.powered or self.mm != MmState.DEREGISTERED:
            return
        if self._reg_attempts == 0:
            self._reg_started_at = self.sim.now
            self.metrics.inc("registration_attempts")
        cell = self._best_cell()
        if cell is None:
            self.metrics.inc("no_suitable_cell")
            self.sim.schedule(1.0, self._start_registration)
            return
        self.mm = MmState.REGISTERED_INITIATED
        self._reg_attempts += 1
        self._t3510 = self.sim.schedule(self.cfg.t3510_s, self._on_t3510_expiry)
        if self.rrc == RrcState.CONNECTED and self.serving is not None:
            self._send_nas(self._registration_request())
        else:
            self.rrc = RrcState.CONNECTING
            self._log("cell_selected", cell=cell.cell_id, rsrp=round(self.rsrp[cell.cell_id], 1))
            cell.rrc_setup_request(self)

    def on_rrc_setup(self, gnb: GNB) -> None:
        if self.rrc != RrcState.CONNECTING:
            return
        self.rrc = RrcState.CONNECTED
        self.serving = gnb
        self._log("rrc_connected", cell=gnb.cell_id)
        gnb.rrc_setup_complete(self, self._registration_request().encode())

    def on_rrc_release(self, gnb: GNB) -> None:
        if gnb is not self.serving:
            return
        self.rrc = RrcState.IDLE
        self.serving = None
        self._log("rrc_idle")

    def _registration_request(self) -> NasMessage:
        return NasMessage(
            MmType.REGISTRATION_REQUEST,
            {
                "registration_type": "initial",
                "ngksi": 7,  # no key available
                "mobile_identity": supi_to_suci(self.usim.supi, self.mcc, self.mnc),
                "ue_security_capability": {"nea": list(self.cfg.nea_supported), "nia": list(self.cfg.nia_supported)},
                "requested_nssai": [{"sst": 1}],
            },
        )

    def _on_t3510_expiry(self) -> None:
        if self.mm != MmState.REGISTERED_INITIATED:
            return
        self.metrics.inc("t3510_expiry")
        self._log("T3510_expired", attempt=self._reg_attempts)
        self.mm = MmState.DEREGISTERED
        self.sec = None
        if self._reg_attempts >= self.cfg.max_registration_attempts:
            self._registration_failed("attempts_exhausted")
            return
        self._start_registration()

    def _registration_failed(self, reason: str) -> None:
        self.metrics.inc("registration_failure")
        self.metrics.inc(f"registration_failure_{reason}")
        self._log("registration_failed", reason=reason)
        self._enter_deregistered()

    def _enter_deregistered(self) -> None:
        if self._t3510:
            self._t3510.cancel()
        self.mm = MmState.DEREGISTERED
        self.sec = None
        self._pending_kamf = None
        self.sessions.clear()

    # ------------------------------------------------------------------ NAS

    def _send_nas(self, msg: NasMessage, header: SecHeader = SecHeader.INTEGRITY_CIPHERED) -> None:
        if self.serving is None:
            return
        pdu = msg.encode()
        if self.sec is not None and header != SecHeader.PLAIN:
            pdu = self.sec.protect(pdu, UPLINK, header)
        self._log(f"tx {msg.name}")
        self.serving.uplink_nas(self, pdu)

    def on_nas(self, gnb: GNB, pdu: bytes) -> None:
        if gnb is not self.serving or not self.powered:
            return
        header = security_header(pdu)
        if header == SecHeader.PLAIN:
            msg = NasMessage.decode(pdu)
            if msg.msg_type not in (
                MmType.AUTHENTICATION_REQUEST,
                MmType.AUTHENTICATION_REJECT,
                MmType.REGISTRATION_REJECT,
                MmType.DEREGISTRATION_ACCEPT_UE_ORIG,
            ):
                self.metrics.inc("ue_plain_message_discarded")
                return
        elif header == SecHeader.INTEGRITY_NEW_CTX:
            msg = self._verify_smc(pdu)
            if msg is None:
                return
        else:
            if self.sec is None:
                self.metrics.inc("ue_protected_without_context")
                return
            try:
                msg = NasMessage.decode(self.sec.unprotect(pdu, DOWNLINK))
            except NasIntegrityError:
                self.metrics.inc("ue_integrity_failure")
                return
        self._log(f"rx {msg.name}")
        handler = {
            MmType.AUTHENTICATION_REQUEST: self._on_auth_request,
            MmType.AUTHENTICATION_REJECT: self._on_auth_reject,
            MmType.SECURITY_MODE_COMMAND: self._on_security_mode_command,
            MmType.REGISTRATION_ACCEPT: self._on_registration_accept,
            MmType.REGISTRATION_REJECT: self._on_registration_reject,
            MmType.DL_NAS_TRANSPORT: self._on_dl_nas_transport,
            MmType.DEREGISTRATION_ACCEPT_UE_ORIG: self._on_deregistration_accept,
        }.get(msg.msg_type)
        if handler:
            handler(msg)

    # 5G-AKA (USIM side) --------------------------------------------------

    def _on_auth_request(self, msg: NasMessage) -> None:
        rand, autn = msg["rand"], msg["autn"]
        sqn_xor_ak, amf_field, mac = autn[:6], autn[6:8], autn[8:16]
        res, ck, ik, ak = self._mil.f2345(rand)
        sqn = xor(sqn_xor_ak, ak)
        xmac, _ = self._mil.f1(rand, sqn, amf_field)
        if xmac != mac:
            self.metrics.inc("ue_mac_failure")
            self._send_nas(NasMessage(MmType.AUTHENTICATION_FAILURE, {"cause": int(MmCause.MAC_FAILURE)}), SecHeader.PLAIN)
            return
        if not amf_field[0] & 0x80:
            self.metrics.inc("ue_amf_separation_bit_missing")
            self._send_nas(NasMessage(MmType.AUTHENTICATION_FAILURE, {"cause": 26}), SecHeader.PLAIN)
            return
        if int.from_bytes(sqn, "big") <= self.usim.sqn_ms:
            self.metrics.inc("ue_sync_failure")
            auts = self._mil.generate_auts(rand, self.usim.sqn_ms.to_bytes(6, "big"))
            self._send_nas(
                NasMessage(MmType.AUTHENTICATION_FAILURE, {"cause": int(MmCause.SYNCH_FAILURE), "auts": auts}),
                SecHeader.PLAIN,
            )
            return
        self.usim.sqn_ms = int.from_bytes(sqn, "big")
        res_star = derive_res_star(ck, ik, self.sn_name, rand, res)
        kausf = derive_kausf(ck, ik, self.sn_name, sqn_xor_ak)
        kseaf = derive_kseaf(kausf, self.sn_name)
        self._pending_kamf = derive_kamf(kseaf, self.usim.supi, msg.ies.get("abba", b"\x00\x00"))
        self.sec = None
        self._send_nas(NasMessage(MmType.AUTHENTICATION_RESPONSE, {"res_star": res_star}), SecHeader.PLAIN)

    def _on_auth_reject(self, msg: NasMessage) -> None:
        self._registration_failed("auth_reject")

    # Security mode control -------------------------------------------------

    def _verify_smc(self, pdu: bytes) -> NasMessage | None:
        if self._pending_kamf is None:
            self.metrics.inc("ue_smc_without_kamf")
            return None
        try:
            peek = NasMessage.decode(pdu[7:])  # SMC is integrity protected only
            nea, nia = peek["nea"], peek["nia"]
            ctx = NasSecurityContext(self._pending_kamf, nea=nea, nia=nia, ngksi=peek["ngksi"])
            msg = NasMessage.decode(ctx.unprotect(pdu, DOWNLINK))
        except (KeyError, ValueError, NasIntegrityError):
            self.metrics.inc("ue_smc_integrity_failure")
            return None
        if msg.msg_type != MmType.SECURITY_MODE_COMMAND:
            return None
        self.sec = ctx
        return msg

    def _on_security_mode_command(self, msg: NasMessage) -> None:
        replayed = msg.ies.get("replayed_ue_security_capability", {})
        expected = {"nea": list(self.cfg.nea_supported), "nia": list(self.cfg.nia_supported)}
        if replayed != expected:
            # Bidding-down protection (TS 33.501 6.7.2).
            self.metrics.inc("ue_smc_capability_mismatch")
            self.sec = None
            return
        self._send_nas(NasMessage(MmType.SECURITY_MODE_COMPLETE, {"imeisv": f"35{self.ue_id:012d}0"}), SecHeader.INTEGRITY_CIPHERED_NEW_CTX)

    # Registration --------------------------------------------------------

    def _on_registration_accept(self, msg: NasMessage) -> None:
        if self.mm != MmState.REGISTERED_INITIATED:
            return
        if self._t3510:
            self._t3510.cancel()
        self.mm = MmState.REGISTERED
        self.guti = msg["guti"]
        self._reg_attempts = 0
        latency = (self.sim.now - self._reg_started_at) * 1000
        self.metrics.registration_latency_ms.append(latency)
        self.metrics.inc("registration_success")
        self._log("registered", guti=self.guti, latency_ms=round(latency, 2))
        self._send_nas(NasMessage(MmType.REGISTRATION_COMPLETE))
        if self.cfg.auto_pdu_session:
            self.establish_pdu_session(1)

    def _on_registration_reject(self, msg: NasMessage) -> None:
        self.last_reject_cause = msg.ies.get("cause")
        self._registration_failed(f"reject_cause_{self.last_reject_cause}")

    # Session management --------------------------------------------------

    def establish_pdu_session(self, psi: int = 1, dnn: str | None = None) -> None:
        if self.mm != MmState.REGISTERED:
            return
        self._pti = self._pti % 254 + 1
        self.sessions[psi] = PduSession(psi=psi, state="PENDING", requested_at=self.sim.now)
        self.metrics.inc("pdu_session_attempts")
        sm = NasMessage(
            SmType.PDU_SESSION_ESTABLISHMENT_REQUEST,
            {"pdu_session_id": psi, "pti": self._pti, "pdu_session_type": "IPv4", "ssc_mode": 1},
            EPD_5GSM,
        )
        self._send_nas(
            NasMessage(
                MmType.UL_NAS_TRANSPORT,
                {
                    "payload_container_type": 1,
                    "payload_container": sm.encode(),
                    "pdu_session_id": psi,
                    "request_type": "initial",
                    "dnn": dnn or self.cfg.dnn,
                    "s_nssai": {"sst": 1},
                },
            )
        )

    def _on_dl_nas_transport(self, msg: NasMessage) -> None:
        sm = NasMessage.decode(msg["payload_container"])
        psi = sm["pdu_session_id"]
        session = self.sessions.get(psi)
        if session is None:
            return
        if sm.msg_type == SmType.PDU_SESSION_ESTABLISHMENT_ACCEPT:
            session.state = "ACTIVE"
            session.ip = sm["pdu_address"]
            latency = (self.sim.now - session.requested_at) * 1000
            self.metrics.pdu_session_latency_ms.append(latency)
            self.metrics.inc("pdu_session_success")
            self._log("pdu_session_active", psi=psi, ip=session.ip, latency_ms=round(latency, 2))
        elif sm.msg_type == SmType.PDU_SESSION_ESTABLISHMENT_REJECT:
            self.sessions.pop(psi, None)
            self.metrics.inc("pdu_session_rejected")
            self._log("pdu_session_rejected", psi=psi, cause=sm.ies.get("cause"))
        elif sm.msg_type == SmType.PDU_SESSION_RELEASE_COMMAND:
            self.sessions.pop(psi, None)

    # Deregistration ---------------------------------------------------------

    def _on_deregistration_accept(self, msg: NasMessage) -> None:
        if self.mm == MmState.DEREGISTERED_INITIATED:
            self.metrics.inc("deregistration_success")
            self._log("deregistered")
            self._enter_deregistered()

    # ------------------------------------------- measurements & mobility

    def _move(self) -> None:
        dt = self.sim.now - self._last_move
        self._last_move = self.sim.now
        m = self.mobility
        if m is None or m.speed_mps <= 0 or self.sim.now < m.pause_until:
            return
        rng = self.sim.rng
        if m.waypoint is None:
            m.waypoint = (rng.uniform(m.area[0], m.area[2]), rng.uniform(m.area[1], m.area[3]))
        wx, wy = m.waypoint
        dist = math.hypot(wx - self.x, wy - self.y)
        step = m.speed_mps * dt
        if step >= dist:
            self.x, self.y = wx, wy
            m.waypoint = None
            m.pause_until = self.sim.now + rng.uniform(0, 5)
        else:
            self.x += (wx - self.x) * step / dist
            self.y += (wy - self.y) * step / dist

    def _measure(self) -> None:
        if not self.powered:
            return
        self._move()
        raw = self.env.measure(self)
        a = 1 / 2 ** (self.cfg.l3_filter_k / 4)  # TS 38.331 layer-3 filtering
        for cid, value in raw.items():
            old = self.rsrp.get(cid)
            self.rsrp[cid] = value if old is None else (1 - a) * old + a * value

        if self.rrc == RrcState.CONNECTED and self.serving is not None and not self._ho_in_progress:
            sinr = self.env.sinr_db(raw, self.serving.cell_id)
            self.metrics.sinr_db.append(sinr)
            self.metrics.throughput_mbps.append(self.env.throughput_mbps(sinr, self.serving.connected_count()))
            self._evaluate_a3()
        self.sim.schedule(self.cfg.measurement_period_s, self._measure)

    def _evaluate_a3(self) -> None:
        """Event A3: neighbour becomes offset better than serving for time-to-trigger."""
        assert self.serving is not None
        serving_level = self.rsrp[self.serving.cell_id]
        candidates = {c: v for c, v in self.rsrp.items() if c != self.serving.cell_id}
        if not candidates:
            return
        best, level = max(candidates.items(), key=lambda kv: kv[1])
        if level <= serving_level + self.cfg.a3_offset_db:
            self._a3 = None
            return
        if self._a3 is None or self._a3[0] != best:
            self._a3 = (best, self.sim.now)
            return
        if self.sim.now - self._a3[1] >= self.cfg.time_to_trigger_s:
            self._a3 = None
            self._ho_in_progress = True
            self._ho_started_at = self.sim.now
            self.metrics.inc("measurement_reports")
            self._log("measurement_report", serving=self.serving.cell_id, target=best,
                      delta_db=round(level - serving_level, 1))
            self.sim.schedule(self.serving._air_delay(), self.serving.measurement_report, self, best)
            self.sim.schedule(1.0, self._ho_guard)

    def _ho_guard(self) -> None:
        if self._ho_in_progress and self.sim.now - self._ho_started_at >= 1.0:
            self._ho_in_progress = False
            self.metrics.inc("handover_failure")

    def on_handover_command(self, source: GNB, target: GNB) -> None:
        if source is not self.serving:
            return
        detached_at = self.sim.now
        self.serving = None
        self._log("handover_command", source=source.cell_id, target=target.cell_id)

        def attach() -> None:
            self.serving = target
            self._ho_in_progress = False
            self.metrics.inc("handover_success")
            self.metrics.ho_interruption_ms.append((self.sim.now - detached_at) * 1000)
            self._log("handover_complete", cell=target.cell_id)
            target.rrc_reconfiguration_complete(self)

        self.sim.schedule(source.latency.ho_interruption, attach)
