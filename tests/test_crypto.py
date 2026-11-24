import pytest

from ue5gsim.crypto import (
    DOWNLINK,
    UPLINK,
    Milenage,
    NasIntegrityError,
    NasSecurityContext,
    SecHeader,
    compute_opc,
    serving_network_name,
)

h = bytes.fromhex

# 3GPP TS 35.208 conformance test set 1
K = h("465b5ce8b199b49faa5f0a2ee238a6bc")
OP = h("cdc202d5123e20f62b6d676ac72cb318")
RAND = h("23553cbe9637a89d218ae64dae47bf35")
SQN = h("ff9bb4d0b607")
AMF = h("b9b9")


def test_opc():
    assert compute_opc(K, OP) == h("cd63cb71954a9f4e48a5994e37a02baf")


def test_f1_f1star():
    mac_a, mac_s = Milenage(K, compute_opc(K, OP)).f1(RAND, SQN, AMF)
    assert mac_a == h("4a9ffac354dfafb3")
    assert mac_s == h("01cfaf9ec4e871e9")


def test_f2345_f5star():
    m = Milenage(K, compute_opc(K, OP))
    res, ck, ik, ak = m.f2345(RAND)
    assert res == h("a54211d5e3ba50bf")
    assert ck == h("b40ba9a3c58b2a05bbf0d987b21bf8cb")
    assert ik == h("f769bcd751044604127672711c6d3441")
    assert ak == h("aa689c648370")
    assert m.f5star(RAND) == h("451e8beca43b")


def test_auts_roundtrip():
    m = Milenage(K, compute_opc(K, OP))
    sqn_ms = (12345).to_bytes(6, "big")
    auts = m.generate_auts(RAND, sqn_ms)
    assert m.recover_sqn_from_auts(RAND, auts) == sqn_ms
    tampered = auts[:-1] + bytes([auts[-1] ^ 1])
    assert m.recover_sqn_from_auts(RAND, tampered) is None


def test_bad_key_length():
    with pytest.raises(ValueError):
        Milenage(b"short", bytes(16))


def test_serving_network_name_pads_mnc():
    assert serving_network_name("208", "93") == "5G:mnc093.mcc208.3gppnetwork.org"


@pytest.mark.parametrize("nea", [0, 2])
def test_nas_protect_unprotect(nea):
    kamf = bytes(range(32))
    ue, net = NasSecurityContext(kamf, nea=nea), NasSecurityContext(kamf, nea=nea)
    for i in range(300):  # crosses the 8-bit SEQ wrap
        plain = b"\x7e\x00\x43" + f"msg{i}".encode()
        pdu = ue.protect(plain, UPLINK, SecHeader.INTEGRITY_CIPHERED)
        if nea:
            assert plain[3:] not in pdu
        assert net.unprotect(pdu, UPLINK) == plain


def test_nas_tamper_and_replay_rejected():
    kamf = bytes(32)
    tx, rx = NasSecurityContext(kamf), NasSecurityContext(kamf)
    pdu = tx.protect(b"\x7e\x00\x68{}", DOWNLINK, SecHeader.INTEGRITY_CIPHERED)
    bad = pdu[:-1] + bytes([pdu[-1] ^ 0xFF])
    with pytest.raises(NasIntegrityError):
        rx.unprotect(bad, DOWNLINK)
    rx.unprotect(pdu, DOWNLINK)
    with pytest.raises(NasIntegrityError):
        rx.unprotect(pdu, DOWNLINK)  # replay
