"""NAS security: 128-NEA2 (AES-CTR) ciphering and 128-NIA2 (AES-CMAC) integrity.

Implements the security-protected 5GS NAS message format of TS 24.501 9.1.1:

    EPD(1) | security header type(1) | MAC(4) | SEQ(1) | plain/ciphered NAS message
"""

from __future__ import annotations

from enum import IntEnum

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

from .kdf import N_NAS_ENC_ALG, N_NAS_INT_ALG, derive_nas_key

UPLINK = 0
DOWNLINK = 1
NAS_BEARER = 0x01  # 3GPP access


class SecHeader(IntEnum):
    PLAIN = 0
    INTEGRITY = 1
    INTEGRITY_CIPHERED = 2
    INTEGRITY_NEW_CTX = 3
    INTEGRITY_CIPHERED_NEW_CTX = 4


class NasIntegrityError(Exception):
    """Raised when a protected NAS PDU fails MAC or replay checks."""


def _count_block(count: int, bearer: int, direction: int) -> bytes:
    return count.to_bytes(4, "big") + bytes([((bearer & 0x1F) << 3) | ((direction & 1) << 2)])


def nia2(key: bytes, count: int, bearer: int, direction: int, message: bytes) -> bytes:
    """128-NIA2: AES-CMAC over COUNT|BEARER|DIRECTION|0^26|MESSAGE, truncated to 32 bits."""
    c = CMAC(algorithms.AES(key))
    c.update(_count_block(count, bearer, direction) + bytes(3) + message)
    return c.finalize()[:4]


def nea2(key: bytes, count: int, bearer: int, direction: int, data: bytes) -> bytes:
    """128-NEA2: AES-CTR with IV = COUNT|BEARER|DIRECTION|0^26|0^64. Symmetric."""
    iv = _count_block(count, bearer, direction) + bytes(11)
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return enc.update(data) + enc.finalize()


class NasSecurityContext:
    """A 5G NAS security context derived from KAMF.

    Algorithm id 0 means the null algorithm (NEA0 / NIA0).
    """

    def __init__(self, kamf: bytes, nea: int = 2, nia: int = 2, ngksi: int = 0):
        if nea not in (0, 2) or nia not in (0, 2):
            raise ValueError("only NEA0/NEA2 and NIA0/NIA2 are implemented")
        self.nea = nea
        self.nia = nia
        self.ngksi = ngksi
        self.k_nas_enc = derive_nas_key(kamf, N_NAS_ENC_ALG, nea)
        self.k_nas_int = derive_nas_key(kamf, N_NAS_INT_ALG, nia)
        self.ul_count = 0
        self.dl_count = 0

    def _mac(self, count: int, direction: int, data: bytes) -> bytes:
        if self.nia == 0:
            return bytes(4)
        return nia2(self.k_nas_int, count, NAS_BEARER, direction, data)

    def _cipher(self, count: int, direction: int, data: bytes) -> bytes:
        if self.nea == 0:
            return data
        return nea2(self.k_nas_enc, count, NAS_BEARER, direction, data)

    def protect(self, plain: bytes, direction: int, header: SecHeader) -> bytes:
        """Wrap a plain NAS message in a security-protected NAS PDU."""
        count = self.ul_count if direction == UPLINK else self.dl_count
        ciphered = header in (SecHeader.INTEGRITY_CIPHERED, SecHeader.INTEGRITY_CIPHERED_NEW_CTX)
        body = self._cipher(count, direction, plain) if ciphered else plain
        seq = bytes([count & 0xFF])
        mac = self._mac(count, direction, seq + body)
        if direction == UPLINK:
            self.ul_count = (self.ul_count + 1) & 0xFFFFFF
        else:
            self.dl_count = (self.dl_count + 1) & 0xFFFFFF
        return bytes([plain[0], int(header)]) + mac + seq + body

    def unprotect(self, pdu: bytes, direction: int) -> bytes:
        """Verify integrity (and replay) and decipher; returns the plain NAS message."""
        if len(pdu) < 8:
            raise NasIntegrityError("PDU too short")
        header = SecHeader(pdu[1] & 0x0F)
        if header == SecHeader.PLAIN:
            raise NasIntegrityError("PDU is not security protected")
        mac, seq, body = pdu[2:6], pdu[6], pdu[7:]
        expected = self.ul_count if direction == UPLINK else self.dl_count
        # Estimate the full COUNT from the 8-bit sequence number (TS 24.501 4.4.3.1).
        count = (expected & ~0xFF) | seq
        if count < expected:
            count += 0x100
        if self._mac(count, direction, bytes([seq]) + body) != mac:
            raise NasIntegrityError("MAC verification failed")
        if direction == UPLINK:
            self.ul_count = (count + 1) & 0xFFFFFF
        else:
            self.dl_count = (count + 1) & 0xFFFFFF
        ciphered = header in (SecHeader.INTEGRITY_CIPHERED, SecHeader.INTEGRITY_CIPHERED_NEW_CTX)
        return self._cipher(count, direction, body) if ciphered else body
