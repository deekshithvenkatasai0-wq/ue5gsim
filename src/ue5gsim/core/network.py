"""A minimal in-process 5G core: AMF + AUSF + UDM/ARPF + SMF.

It is the test peer for the UE: it runs 5G-AKA, NAS security mode control,
registration, PDU session establishment and UE-initiated deregistration.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..crypto import (
    DOWNLINK,
    UPLINK,
    Milenage,
    NasIntegrityError,
    NasSecurityContext,
    SecHeader,
    derive_hres_star,
    derive_kamf,
    derive_kausf,
    derive_kseaf,
    derive_res_star,
    serving_network_name,
    xor,
)
from ..nas import (
    EPD_5GSM,
    MmCause,
    MmType,
    NasMessage,
    SmCause,
    SmType,
    security_header,
    suci_to_supi,
)

if TYPE_CHECKING:
    from ..engine import Simulator
    from ..metrics import Metrics
    from ..ran.gnb import GNB

# Messages the AMF accepts without NAS security (TS 24.501 4.4.4.3).
PLAIN_ALLOWED_UL = {
    MmType.REGISTRATION_REQUEST,
    MmType.AUTHENTICATION_RESPONSE,
    MmType.AUTHENTICATION_FAILURE,
    MmType.DEREGISTRATION_REQUEST_UE_ORIG,
}


@dataclass
class Subscription:
    supi: str
    k: bytes
    opc: bytes
    sqn: int = 0
    amf_field: bytes = b"\x80\x00"  # separation bit set for 5G
    dnns: tuple[str, ...] = ("internet",)


@dataclass
class AuthVector:
    rand: bytes
    xres_star: bytes
    hxres_star: bytes
    kseaf: bytes


@dataclass
class AmfUeContext:
    ran_ue_id: int
    gnb: GNB
    supi: str | None = None
    state: str = "DEREGISTERED"
    av: AuthVector | None = None
    sec: NasSecurityContext | None = None
    ue_caps: dict = field(default_factory=dict)
    guti: str | None = None
    ngksi: int = 0
    sessions: dict[int, str] = field(default_factory=dict)


class CoreNetwork:
    def __init__(
        self,
        sim: Simulator,
        metrics: Metrics,
        mcc: str = "208",
        mnc: str = "93",
        ue_ip_pool: str = "10.45.0.0/16",
        processing_delay: float = 0.001,
    ):
        self.sim = sim
        self.metrics = metrics
        self.mcc = mcc
        self.mnc = mnc
        self.sn_name = serving_network_name(mcc, mnc)
        self.processing_delay = processing_delay
        self.subscribers: dict[str, Subscription] = {}
        self.contexts: dict[int, AmfUeContext] = {}
        self._pool = ipaddress.ip_network(ue_ip_pool).hosts()
        self._free_ips: list[str] = []
        self._next_tmsi = 1

    # --- provisioning ------------------------------------------------------

    def add_subscriber(self, sub: Subscription) -> None:
        self.subscribers[sub.supi] = sub

    # --- N2 entry points ---------------------------------------------------

    def initial_ue_message(self, gnb: GNB, ran_ue_id: int, pdu: bytes) -> None:
        self.contexts[ran_ue_id] = AmfUeContext(ran_ue_id=ran_ue_id, gnb=gnb)
        self._receive(self.contexts[ran_ue_id], pdu)

    def uplink_nas(self, gnb: GNB, ran_ue_id: int, pdu: bytes) -> None:
        ctx = self.contexts.get(ran_ue_id)
        if ctx is None:
            self.metrics.inc("amf_ul_no_context")
            return
        ctx.gnb = gnb
        self._receive(ctx, pdu)

    def path_switch(self, gnb: GNB, ran_ue_id: int) -> None:
        ctx = self.contexts.get(ran_ue_id)
        if ctx is not None:
            ctx.gnb = gnb
            self.metrics.inc("path_switch")

    # --- NAS handling ------------------------------------------------------

    def _receive(self, ctx: AmfUeContext, pdu: bytes) -> None:
        if security_header(pdu) != SecHeader.PLAIN:
            if ctx.sec is None:
                self.metrics.inc("amf_protected_without_context")
                return
            try:
                pdu = ctx.sec.unprotect(pdu, UPLINK)
            except NasIntegrityError:
                self.metrics.inc("amf_integrity_failure")
                return
            msg = NasMessage.decode(pdu)
        else:
            msg = NasMessage.decode(pdu)
            if msg.msg_type not in PLAIN_ALLOWED_UL:
                self.metrics.inc("amf_plain_message_discarded")
                return
        self.metrics.log(self.sim.now, "AMF", f"rx {msg.name}", ue=ctx.ran_ue_id)
        handler = {
            MmType.REGISTRATION_REQUEST: self._on_registration_request,
            MmType.AUTHENTICATION_RESPONSE: self._on_auth_response,
            MmType.AUTHENTICATION_FAILURE: self._on_auth_failure,
            MmType.SECURITY_MODE_COMPLETE: self._on_smc_complete,
            MmType.REGISTRATION_COMPLETE: self._on_registration_complete,
            MmType.UL_NAS_TRANSPORT: self._on_ul_nas_transport,
            MmType.DEREGISTRATION_REQUEST_UE_ORIG: self._on_deregistration,
        }.get(msg.msg_type)
        if handler is None:
            self.metrics.inc("amf_unhandled_message")
            return
        handler(ctx, msg)

    def _send(self, ctx: AmfUeContext, msg: NasMessage, header: SecHeader = SecHeader.INTEGRITY_CIPHERED) -> None:
        pdu = msg.encode()
        if header != SecHeader.PLAIN:
            assert ctx.sec is not None
            pdu = ctx.sec.protect(pdu, DOWNLINK, header)
        self.metrics.log(self.sim.now, "AMF", f"tx {msg.name}", ue=ctx.ran_ue_id)
        self.sim.schedule(
            self.processing_delay + ctx.gnb.latency.n2, ctx.gnb.downlink_nas, ctx.ran_ue_id, pdu
        )

    def _release(self, ctx: AmfUeContext, delay: float = 0.05) -> None:
        for ip in ctx.sessions.values():
            self._free_ips.append(ip)
        ctx.sessions.clear()
        self.contexts.pop(ctx.ran_ue_id, None)
        self.sim.schedule(delay, ctx.gnb.ue_context_release, ctx.ran_ue_id)

    # Registration / 5G-AKA --------------------------------------------------

    def _on_registration_request(self, ctx: AmfUeContext, msg: NasMessage) -> None:
        try:
            supi = suci_to_supi(msg["mobile_identity"])
        except (KeyError, ValueError):
            self._reject(ctx, MmCause.ILLEGAL_UE)
            return
        sub = self.subscribers.get(supi)
        if sub is None:
            self.metrics.inc("amf_unknown_subscriber")
            self._reject(ctx, MmCause.ILLEGAL_UE)
            return
        ctx.supi = supi
        ctx.ue_caps = msg.ies.get("ue_security_capability", {})
        ctx.sec = None
        ctx.state = "REGISTRATION_INITIATED"
        self._start_authentication(ctx, sub)

    def _reject(self, ctx: AmfUeContext, cause: MmCause) -> None:
        self._send(ctx, NasMessage(MmType.REGISTRATION_REJECT, {"cause": int(cause)}), SecHeader.PLAIN)
        self._release(ctx)

    def _start_authentication(self, ctx: AmfUeContext, sub: Subscription) -> None:
        """UDM/ARPF generates a 5G HE AV; AUSF and SEAF keep their parts."""
        sub.sqn += 1
        sqn = sub.sqn.to_bytes(6, "big")
        rand = self.sim.rng.randbytes(16)
        mil = Milenage(sub.k, sub.opc)
        autn = mil.generate_autn(rand, sqn, sub.amf_field)
        res, ck, ik, ak = mil.f2345(rand)
        xres_star = derive_res_star(ck, ik, self.sn_name, rand, res)
        kausf = derive_kausf(ck, ik, self.sn_name, xor(sqn, ak))
        ctx.av = AuthVector(
            rand=rand,
            xres_star=xres_star,
            hxres_star=derive_hres_star(rand, xres_star),
            kseaf=derive_kseaf(kausf, self.sn_name),
        )
        ctx.ngksi = (ctx.ngksi + 1) % 7
        req = NasMessage(
            MmType.AUTHENTICATION_REQUEST,
            {"ngksi": ctx.ngksi, "abba": b"\x00\x00", "rand": rand, "autn": autn},
        )
        self._send(ctx, req, SecHeader.PLAIN)

    def _on_auth_response(self, ctx: AmfUeContext, msg: NasMessage) -> None:
        av = ctx.av
        res_star = msg.ies.get("res_star", b"")
        # SEAF checks HRES* against HXRES*, then AUSF checks RES* against XRES*.
        if av is None or derive_hres_star(av.rand, res_star) != av.hxres_star or res_star != av.xres_star:
            self.metrics.inc("amf_auth_rejected")
            self._send(ctx, NasMessage(MmType.AUTHENTICATION_REJECT), SecHeader.PLAIN)
            self._release(ctx)
            return
        assert ctx.supi is not None
        kamf = derive_kamf(av.kseaf, ctx.supi)
        nea = 2 if 2 in ctx.ue_caps.get("nea", []) else 0
        ctx.sec = NasSecurityContext(kamf, nea=nea, nia=2, ngksi=ctx.ngksi)
        smc = NasMessage(
            MmType.SECURITY_MODE_COMMAND,
            {
                "nea": nea,
                "nia": 2,
                "ngksi": ctx.ngksi,
                "replayed_ue_security_capability": ctx.ue_caps,
                "abba": b"\x00\x00",
            },
        )
        self._send(ctx, smc, SecHeader.INTEGRITY_NEW_CTX)

    def _on_auth_failure(self, ctx: AmfUeContext, msg: NasMessage) -> None:
        cause = msg.ies.get("cause")
        sub = self.subscribers.get(ctx.supi or "")
        if cause == MmCause.SYNCH_FAILURE and sub is not None and ctx.av is not None:
            sqn_ms = Milenage(sub.k, sub.opc).recover_sqn_from_auts(ctx.av.rand, msg.ies.get("auts", b""))
            if sqn_ms is not None:
                self.metrics.inc("amf_sqn_resync")
                sub.sqn = int.from_bytes(sqn_ms, "big")
                self._start_authentication(ctx, sub)
                return
        self.metrics.inc("amf_auth_failure")
        self._send(ctx, NasMessage(MmType.AUTHENTICATION_REJECT), SecHeader.PLAIN)
        self._release(ctx)

    def _on_smc_complete(self, ctx: AmfUeContext, msg: NasMessage) -> None:
        tmsi = self._next_tmsi
        self._next_tmsi += 1
        ctx.guti = f"5g-guti-{self.mcc}{self.mnc}cafe00{tmsi:08x}"
        accept = NasMessage(
            MmType.REGISTRATION_ACCEPT,
            {
                "result": "3gpp_access",
                "guti": ctx.guti,
                "tai_list": [{"mcc": self.mcc, "mnc": self.mnc, "tac": 1}],
                "allowed_nssai": [{"sst": 1}],
                "t3512_s": 3240,
            },
        )
        self._send(ctx, accept)

    def _on_registration_complete(self, ctx: AmfUeContext, msg: NasMessage) -> None:
        ctx.state = "REGISTERED"
        self.metrics.inc("amf_registered")

    # Session management (SMF) -----------------------------------------------

    def _allocate_ip(self) -> str | None:
        if self._free_ips:
            return self._free_ips.pop()
        addr = next(self._pool, None)
        return str(addr) if addr is not None else None

    def _on_ul_nas_transport(self, ctx: AmfUeContext, msg: NasMessage) -> None:
        sm = NasMessage.decode(msg["payload_container"])
        if sm.msg_type == SmType.PDU_SESSION_ESTABLISHMENT_REQUEST:
            self._establish_session(ctx, msg, sm)
        elif sm.msg_type == SmType.PDU_SESSION_RELEASE_REQUEST:
            psi = sm["pdu_session_id"]
            ip = ctx.sessions.pop(psi, None)
            if ip:
                self._free_ips.append(ip)
            cmd = NasMessage(SmType.PDU_SESSION_RELEASE_COMMAND, {"pdu_session_id": psi, "pti": sm["pti"], "cause": 36}, EPD_5GSM)
            self._send_sm(ctx, psi, cmd)

    def _establish_session(self, ctx: AmfUeContext, msg: NasMessage, sm: NasMessage) -> None:
        sub = self.subscribers[ctx.supi]  # type: ignore[index]
        psi, pti = sm["pdu_session_id"], sm["pti"]
        dnn = msg.ies.get("dnn", sub.dnns[0])
        ip = self._allocate_ip() if dnn in sub.dnns else None
        if ip is None:
            cause = SmCause.MISSING_OR_UNKNOWN_DNN if dnn not in sub.dnns else SmCause.INSUFFICIENT_RESOURCES
            self.metrics.inc("smf_session_rejected")
            rej = NasMessage(SmType.PDU_SESSION_ESTABLISHMENT_REJECT, {"pdu_session_id": psi, "pti": pti, "cause": int(cause)}, EPD_5GSM)
            self._send_sm(ctx, psi, rej)
            return
        ctx.sessions[psi] = ip
        self.metrics.inc("smf_session_established")
        acc = NasMessage(
            SmType.PDU_SESSION_ESTABLISHMENT_ACCEPT,
            {
                "pdu_session_id": psi,
                "pti": pti,
                "selected_pdu_session_type": "IPv4",
                "selected_ssc_mode": 1,
                "pdu_address": ip,
                "dnn": dnn,
                "session_ambr": {"dl_mbps": 1000, "ul_mbps": 500},
                "qos_rules": [{"qfi": 9, "default": True, "5qi": 9}],
            },
            EPD_5GSM,
        )
        self._send_sm(ctx, psi, acc)

    def _send_sm(self, ctx: AmfUeContext, psi: int, sm: NasMessage) -> None:
        dl = NasMessage(
            MmType.DL_NAS_TRANSPORT,
            {"payload_container_type": 1, "payload_container": sm.encode(), "pdu_session_id": psi},
        )
        self._send(ctx, dl)

    # Deregistration ------------------------------------------------------------

    def _on_deregistration(self, ctx: AmfUeContext, msg: NasMessage) -> None:
        ctx.state = "DEREGISTERED"
        self.metrics.inc("amf_deregistered")
        if not msg.ies.get("switch_off", False):
            header = SecHeader.INTEGRITY_CIPHERED if ctx.sec else SecHeader.PLAIN
            self._send(ctx, NasMessage(MmType.DEREGISTRATION_ACCEPT_UE_ORIG), header)
        self._release(ctx)
