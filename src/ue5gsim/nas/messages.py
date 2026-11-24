"""5GS NAS message model (TS 24.501).

Message type codes, cause values and protocol discriminators follow TS 24.501.
Information elements are carried as a compact, deterministic key/value body
instead of the full TLV wire format; see README "Scope" for the roadmap to a
complete codec.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

EPD_5GMM = 0x7E
EPD_5GSM = 0x2E


class MmType(IntEnum):
    """5GMM message types (TS 24.501 Table 9.7.1)."""

    REGISTRATION_REQUEST = 0x41
    REGISTRATION_ACCEPT = 0x42
    REGISTRATION_COMPLETE = 0x43
    REGISTRATION_REJECT = 0x44
    DEREGISTRATION_REQUEST_UE_ORIG = 0x45
    DEREGISTRATION_ACCEPT_UE_ORIG = 0x46
    SERVICE_REQUEST = 0x4C
    AUTHENTICATION_REQUEST = 0x56
    AUTHENTICATION_RESPONSE = 0x57
    AUTHENTICATION_REJECT = 0x58
    AUTHENTICATION_FAILURE = 0x59
    SECURITY_MODE_COMMAND = 0x5D
    SECURITY_MODE_COMPLETE = 0x5E
    UL_NAS_TRANSPORT = 0x67
    DL_NAS_TRANSPORT = 0x68


class SmType(IntEnum):
    """5GSM message types (TS 24.501 Table 9.7.2)."""

    PDU_SESSION_ESTABLISHMENT_REQUEST = 0xC1
    PDU_SESSION_ESTABLISHMENT_ACCEPT = 0xC2
    PDU_SESSION_ESTABLISHMENT_REJECT = 0xC3
    PDU_SESSION_RELEASE_REQUEST = 0xD1
    PDU_SESSION_RELEASE_COMMAND = 0xD3
    PDU_SESSION_RELEASE_COMPLETE = 0xD4


class MmCause(IntEnum):
    """Selected 5GMM cause values (TS 24.501 9.11.3.2)."""

    ILLEGAL_UE = 3
    PLMN_NOT_ALLOWED = 11
    MAC_FAILURE = 20
    SYNCH_FAILURE = 21
    NGKSI_ALREADY_IN_USE = 71


class SmCause(IntEnum):
    """Selected 5GSM cause values (TS 24.501 9.11.4.2)."""

    MISSING_OR_UNKNOWN_DNN = 27
    INSUFFICIENT_RESOURCES = 26


def _pack(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"$b": value.hex()}
    if isinstance(value, dict):
        return {k: _pack(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_pack(v) for v in value]
    return value


def _unpack(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"$b"}:
            return bytes.fromhex(value["$b"])
        return {k: _unpack(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_unpack(v) for v in value]
    return value


@dataclass
class NasMessage:
    msg_type: int
    ies: dict[str, Any] = field(default_factory=dict)
    epd: int = EPD_5GMM

    def encode(self) -> bytes:
        body = json.dumps(_pack(self.ies), separators=(",", ":"), sort_keys=True).encode()
        return bytes([self.epd, 0x00, self.msg_type]) + body

    @classmethod
    def decode(cls, data: bytes) -> NasMessage:
        if len(data) < 3:
            raise ValueError("NAS message too short")
        epd, msg_type = data[0], data[2]
        ies = _unpack(json.loads(data[3:])) if len(data) > 3 else {}
        return cls(msg_type=msg_type, ies=ies, epd=epd)

    @property
    def name(self) -> str:
        enum = MmType if self.epd == EPD_5GMM else SmType
        try:
            return enum(self.msg_type).name
        except ValueError:
            return f"UNKNOWN_0x{self.msg_type:02X}"

    def __getitem__(self, key: str) -> Any:
        return self.ies[key]


def security_header(pdu: bytes) -> int:
    return pdu[1] & 0x0F if len(pdu) > 1 else 0


# --- Identities -----------------------------------------------------------

def supi_to_suci(supi: str, mcc: str, mnc: str) -> str:
    """Conceal a SUPI with the null protection scheme (TS 23.003 2.2B)."""
    imsi = supi.removeprefix("imsi-")
    msin = imsi[len(mcc) + len(mnc):]
    return f"suci-0-{mcc}-{mnc}-0000-0-0-{msin}"


def suci_to_supi(suci: str) -> str:
    parts = suci.split("-")
    if len(parts) != 8 or parts[0] != "suci" or parts[5] != "0":
        raise ValueError(f"unsupported SUCI {suci!r} (only null scheme is implemented)")
    _, _, mcc, mnc, _, _, _, msin = parts
    return f"imsi-{mcc}{mnc}{msin}"
