"""End-to-end NAS procedures between the UE and the in-process core."""

from ue5gsim import (
    GNB,
    UE,
    CoreNetwork,
    Metrics,
    MmState,
    Mobility,
    RadioEnvironment,
    RrcState,
    Simulator,
    Subscription,
    UsimProfile,
)
from ue5gsim.crypto import compute_opc
from ue5gsim.nas import MmCause, suci_to_supi, supi_to_suci

MCC, MNC = "208", "93"
K = bytes(range(16))
OPC = compute_opc(K, bytes(16))


def build(num_cells=1, isd=500.0, seed=1):
    sim = Simulator(seed=seed)
    metrics = Metrics(trace_enabled=True)
    core = CoreNetwork(sim, metrics, MCC, MNC)
    env = RadioEnvironment(sim.rng, shadow_std_db=0.0)
    cells = [GNB(sim, i + 1, i * isd, 0.0, core, metrics) for i in range(num_cells)]
    for c in cells:
        env.add_cell(c)
        c.neighbours = {n.cell_id: n for n in cells if n is not c}
    return sim, metrics, core, env, cells


def make_ue(sim, metrics, env, ue_id=1, k=K, sqn_ms=0, provision=None, x=100.0, y=50.0, mobility=None):
    supi = f"imsi-{MCC}{MNC}{ue_id:010d}"
    if provision is not None:
        provision.add_subscriber(Subscription(supi, K, OPC))
    return UE(sim, ue_id, UsimProfile(supi, k, compute_opc(k, bytes(16)), sqn_ms), MCC, MNC, env, metrics, x, y, mobility)


def test_suci_roundtrip():
    supi = "imsi-208930000000001"
    suci = supi_to_suci(supi, MCC, MNC)
    assert suci == "suci-0-208-93-0000-0-0-0000000001"
    assert suci_to_supi(suci) == supi


def test_registration_and_pdu_session():
    sim, metrics, core, env, _ = build()
    ue = make_ue(sim, metrics, env, provision=core)
    sim.schedule(0.0, ue.power_on)
    sim.run(until=2.0)
    assert ue.mm == MmState.REGISTERED
    assert ue.rrc == RrcState.CONNECTED
    assert ue.guti and ue.guti.startswith("5g-guti-")
    assert ue.sessions[1].state == "ACTIVE"
    assert ue.sessions[1].ip == "10.45.0.1"
    assert metrics.counters["registration_success"] == 1
    assert 0 < metrics.registration_latency_ms[0] < 200


def test_unknown_subscriber_rejected():
    sim, metrics, core, env, _ = build()
    ue = make_ue(sim, metrics, env, provision=None)
    sim.schedule(0.0, ue.power_on)
    sim.run(until=2.0)
    assert ue.mm == MmState.DEREGISTERED
    assert ue.last_reject_cause == MmCause.ILLEGAL_UE
    assert ue.rrc == RrcState.IDLE


def test_sqn_resynchronisation():
    sim, metrics, core, env, _ = build()
    ue = make_ue(sim, metrics, env, sqn_ms=5000, provision=core)
    sim.schedule(0.0, ue.power_on)
    sim.run(until=2.0)
    assert metrics.counters["ue_sync_failure"] == 1
    assert metrics.counters["amf_sqn_resync"] == 1
    assert ue.mm == MmState.REGISTERED
    assert ue.usim.sqn_ms == 5001


def test_wrong_key_fails_authentication():
    sim, metrics, core, env, _ = build()
    ue = make_ue(sim, metrics, env, k=bytes(16), provision=core)
    sim.schedule(0.0, ue.power_on)
    sim.run(until=2.0)
    assert metrics.counters["ue_mac_failure"] == 1
    assert metrics.counters["registration_failure_auth_reject"] == 1
    assert ue.mm == MmState.DEREGISTERED


def test_deregistration_releases_session():
    sim, metrics, core, env, _ = build()
    ue = make_ue(sim, metrics, env, provision=core)
    sim.schedule(0.0, ue.power_on)
    sim.schedule(1.0, ue.deregister)
    sim.run(until=2.0)
    assert metrics.counters["deregistration_success"] == 1
    assert ue.mm == MmState.DEREGISTERED
    assert ue.rrc == RrcState.IDLE
    assert core.contexts == {}


def test_handover_between_cells():
    sim, metrics, core, env, cells = build(num_cells=2, isd=500.0)
    mob = Mobility(speed_mps=30.0, area=(0, 0, 500, 0), waypoint=(480.0, 0.0))
    ue = make_ue(sim, metrics, env, provision=core, x=20.0, y=0.0, mobility=mob)
    sim.schedule(0.0, ue.power_on)
    sim.run(until=20.0)
    assert metrics.counters["handover_success"] >= 1
    assert ue.serving is cells[1]
    assert core.contexts[ue.ue_id].gnb is cells[1]
    assert ue.mm == MmState.REGISTERED


def test_simulation_is_deterministic():
    def run():
        sim, metrics, core, env, _ = build(num_cells=3, seed=7)
        for i in range(1, 6):
            ue = make_ue(sim, metrics, env, ue_id=i, provision=core, x=100.0 * i)
            sim.schedule(0.1 * i, ue.power_on)
        sim.run(until=3.0)
        return metrics.summary()

    assert run() == run()
