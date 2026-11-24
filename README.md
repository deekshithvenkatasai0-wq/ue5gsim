# ue5gsim

An open-source **5G UE simulator** in Python. It models a UE's control plane end to end against a minimal in-process 5G core, inside a deterministic discrete-event simulation.

> Status: early alpha (v0.1.0). APIs may change.

## Features

- **USIM / 5G-AKA**: MILENAGE f1–f5* (verified against 3GPP TS 35.208 test set 1), AUTN/AUTS, SQN freshness and resynchronisation
- **5G key hierarchy** (TS 33.501): RES*, HRES*, K_AUSF, K_SEAF, K_AMF, K_NASenc / K_NASint
- **NAS security**: 128-NEA2 (AES-CTR) and 128-NIA2 (AES-CMAC), COUNT handling, replay protection, bidding-down check
- **5GMM**: registration (with T3510 retries), security mode control, deregistration, reject handling
- **5GSM**: PDU session establishment / release via UL/DL NAS Transport, IP allocation
- **SUCI** null-scheme concealment
- **RAN**: RRC setup/release, TR 38.901 UMa path loss, correlated shadowing, SINR, CQI, throughput
- **Mobility**: random-waypoint movement, L3 filtering, event A3 with time-to-trigger, Xn handover with path switch
- **Core**: AMF + AUSF + UDM + SMF test peer
- KPIs: registration / PDU-session latency, handover interruption, SINR, throughput

## Install

```bash
pip install git+https://github.com/deekshithvenkatasai0-wq/ue5gsim.git
```

## Quick example

```python
from ue5gsim import *
from ue5gsim.crypto import compute_opc

sim = Simulator(seed=1); metrics = Metrics(trace_enabled=True)
core = CoreNetwork(sim, metrics, mcc="208", mnc="93")
env = RadioEnvironment(sim.rng)
gnb = GNB(sim, 1, 0, 0, core, metrics); env.add_cell(gnb)

k, op = bytes(range(16)), bytes(16)
opc = compute_opc(k, op)
supi = "imsi-208930000000001"
core.add_subscriber(Subscription(supi, k, opc))
ue = UE(sim, 1, UsimProfile(supi, k, opc), "208", "93", env, metrics, x=200, y=100)

sim.schedule(0.0, ue.power_on)
sim.run(until=5)
print(ue.mm, ue.sessions[1].ip)
print(metrics.summary())
```

## Scope and limitations

NAS message types, cause codes and security procedures follow TS 24.501 / 33.501, but information elements use a simplified key/value body rather than the full TLV wire encoding, so it is not yet wire-compatible with real AMFs (e.g. Open5GS, free5GC).

## Roadmap

- Full TS 24.501 TLV codec and NGAP/SCTP to connect to real cores
- SUCI Profile A/B (ECIES), service request, RRC inactive, multi-slice
- Scenario runner CLI, test suite and CI

## Licence

MIT
