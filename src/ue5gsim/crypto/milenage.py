"""MILENAGE authentication and key generation functions (3GPP TS 35.205 / 35.206).

Implements f1, f1*, f2, f3, f4, f5 and f5* on top of AES-128.
Verified against the conformance test sets in TS 35.207 / 35.208.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Rotation amounts (in bytes) and constants c1..c5 from TS 35.206 section 4.1.
_R = (8, 0, 4, 8, 12)
_C = tuple(bytes(15) + bytes([v]) for v in (0x00, 0x01, 0x02, 0x04, 0x08))


def xor(a: bytes, b: bytes) -> bytes:
    """Byte-wise XOR of two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("xor operands must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def _aes(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _rot(x: bytes, r_bytes: int) -> bytes:
    """Cyclic left rotation by r_bytes * 8 bits."""
    return x[r_bytes:] + x[:r_bytes]


def compute_opc(k: bytes, op: bytes) -> bytes:
    """Derive OPc = E_K(OP) xor OP."""
    _check(k, 16, "K")
    _check(op, 16, "OP")
    return xor(_aes(k, op), op)


def _check(value: bytes, length: int, name: str) -> None:
    if len(value) != length:
        raise ValueError(f"{name} must be {length} bytes, got {len(value)}")


class Milenage:
    """MILENAGE algorithm set bound to a subscriber key K and operator key OPc."""

    def __init__(self, k: bytes, opc: bytes):
        _check(k, 16, "K")
        _check(opc, 16, "OPc")
        self.k = k
        self.opc = opc

    def _temp(self, rand: bytes) -> bytes:
        _check(rand, 16, "RAND")
        return _aes(self.k, xor(rand, self.opc))

    def _out(self, temp: bytes, i: int) -> bytes:
        """OUT2..OUT5 (i = 1..4)."""
        x = xor(_rot(xor(temp, self.opc), _R[i]), _C[i])
        return xor(_aes(self.k, x), self.opc)

    def f1(self, rand: bytes, sqn: bytes, amf: bytes) -> tuple[bytes, bytes]:
        """Return (MAC-A, MAC-S): network authentication and resync codes."""
        _check(sqn, 6, "SQN")
        _check(amf, 2, "AMF")
        temp = self._temp(rand)
        in1 = sqn + amf + sqn + amf
        x = xor(temp, xor(_rot(xor(in1, self.opc), _R[0]), _C[0]))
        out1 = xor(_aes(self.k, x), self.opc)
        return out1[:8], out1[8:]

    def f2345(self, rand: bytes) -> tuple[bytes, bytes, bytes, bytes]:
        """Return (RES, CK, IK, AK)."""
        temp = self._temp(rand)
        out2 = self._out(temp, 1)
        out3 = self._out(temp, 2)
        out4 = self._out(temp, 3)
        return out2[8:], out3, out4, out2[:6]

    def f5star(self, rand: bytes) -> bytes:
        """Return AK* used to conceal SQN_MS in the AUTS resync token."""
        return self._out(self._temp(rand), 4)[:6]

    # Convenience helpers used by both the UE (USIM) and the network (UDM/ARPF).

    def generate_autn(self, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
        """AUTN = (SQN xor AK) || AMF || MAC-A."""
        mac_a, _ = self.f1(rand, sqn, amf)
        _, _, _, ak = self.f2345(rand)
        return xor(sqn, ak) + amf + mac_a

    def generate_auts(self, rand: bytes, sqn_ms: bytes) -> bytes:
        """AUTS = (SQN_MS xor AK*) || MAC-S, computed with the dummy AMF 0x0000."""
        _, mac_s = self.f1(rand, sqn_ms, b"\x00\x00")
        return xor(sqn_ms, self.f5star(rand)) + mac_s

    def recover_sqn_from_auts(self, rand: bytes, auts: bytes) -> bytes | None:
        """Network side: extract SQN_MS from AUTS; None if MAC-S does not verify."""
        _check(auts, 14, "AUTS")
        sqn_ms = xor(auts[:6], self.f5star(rand))
        _, mac_s = self.f1(rand, sqn_ms, b"\x00\x00")
        return sqn_ms if mac_s == auts[6:] else None
