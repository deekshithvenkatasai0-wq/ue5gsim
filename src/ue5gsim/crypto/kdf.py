"""5G key hierarchy derivation (3GPP TS 33.501 Annex A, KDF from TS 33.220 Annex B)."""

from __future__ import annotations

import hashlib
import hmac

# FC values from TS 33.501 Annex A.
FC_KAUSF = 0x6A
FC_RES_STAR = 0x6B
FC_KSEAF = 0x6C
FC_KAMF = 0x6D
FC_ALG_KEY = 0x69

# Algorithm type distinguishers (TS 33.501 Annex A.8).
N_NAS_ENC_ALG = 0x01
N_NAS_INT_ALG = 0x02


def kdf(key: bytes, fc: int, *params: bytes) -> bytes:
    """Generic 3GPP KDF: HMAC-SHA-256(key, FC || P0 || L0 || P1 || L1 ...)."""
    s = bytes([fc])
    for p in params:
        s += p + len(p).to_bytes(2, "big")
    return hmac.new(key, s, hashlib.sha256).digest()


def serving_network_name(mcc: str, mnc: str) -> str:
    """SN name as defined in TS 24.501 9.12.1, e.g. 5G:mnc093.mcc208.3gppnetwork.org."""
    return f"5G:mnc{mnc.zfill(3)}.mcc{mcc}.3gppnetwork.org"


def derive_kausf(ck: bytes, ik: bytes, sn_name: str, sqn_xor_ak: bytes) -> bytes:
    return kdf(ck + ik, FC_KAUSF, sn_name.encode(), sqn_xor_ak)


def derive_res_star(ck: bytes, ik: bytes, sn_name: str, rand: bytes, res: bytes) -> bytes:
    """RES* / XRES* = 128 least significant bits of the KDF output."""
    return kdf(ck + ik, FC_RES_STAR, sn_name.encode(), rand, res)[16:]


def derive_hres_star(rand: bytes, res_star: bytes) -> bytes:
    """HRES* / HXRES* = 128 least significant bits of SHA-256(RAND || RES*)."""
    return hashlib.sha256(rand + res_star).digest()[16:]


def derive_kseaf(kausf: bytes, sn_name: str) -> bytes:
    return kdf(kausf, FC_KSEAF, sn_name.encode())


def derive_kamf(kseaf: bytes, supi: str, abba: bytes = b"\x00\x00") -> bytes:
    """SUPI is passed as the IMSI digit string (without the 'imsi-' prefix)."""
    digits = supi.removeprefix("imsi-")
    return kdf(kseaf, FC_KAMF, digits.encode(), abba)


def derive_nas_key(kamf: bytes, distinguisher: int, alg_id: int) -> bytes:
    """KNASenc / KNASint: 128 least significant bits of the KDF output."""
    return kdf(kamf, FC_ALG_KEY, bytes([distinguisher]), bytes([alg_id]))[16:]
