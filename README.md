# AINA prototype harness

This is a re-implementation of the prototype and evaluation for *"AI-Native Network Architecture:
Explicit Contracts for Semantic Intent, Cognitive Artifacts, and Autonomous Coordination in
Distributed Intelligent Systems"* (IJECE paper ID 42852), rebuilt for the revision with an
expanded experimental protocol.

The core harness uses only the Python standard library (3.9 or later). The analysis and figures
need `numpy` and `matplotlib`.

## Reproduce everything

```bash
python -m unittest discover -s tests -v      # 21 tests: contracts, invariants, evolution, adapters
pip install -r requirements.txt               # numpy + matplotlib, for analysis only
python analysis/analyze.py                   # regenerates RESULTS.md, tables/, figures/ from the shipped raw data
python experiments/run.py all                # optional: re-runs every experiment (~20-30 min on 2 cores)
```

## Data

`results/raw/*.jsonl.gz` holds one row per executed request (76,000 rows in total) with the condition, seed, case, scale, fault rate, latency, bytes, answer, correctness, and fault-injection and localization counts. `results/raw/*.config.json` records the parameters of each experiment, and `results/environment.json` records the machine. Re-running the experiments writes uncompressed `.jsonl` files, which the analysis reads in preference to the compressed ones.

## Layout

| Path | What it is |
|---|---|
| `aina/schemas/*.schema.json` | Machine-readable contracts: IntentFrame, EvidenceBundle, DelegationGraph (JSON Schema 2020-12) |
| `aina/contracts.py` | Validator, semantic predicates (cross-field rules), versioning rule, slim-baseline checks |
| `aina/workload.py` | Synthetic SIEM/EDR incident-triage workload with ground truth; indicator catalog |
| `aina/intent.py` | Canonical request normalizer (v2) and the older parser (v1) used to model interpretation drift |
| `aina/reasoning.py` | Retrieval scoring, correlation, synthesis. **All conditions share this code.** |
| `aina/variants.py` | The 11 backend variants and their producer-side adapters |
| `aina/faults.py` | Deterministic fault schedule (timeout / malformed / empty) |
| `aina/services.py` | Intent, retrieval, correlator, and synthesis services; dispatcher; fault injection |
| `aina/transport.py` | Multi-process HTTP/1.1 deployment over localhost, plus an in-process client for tests |
| `aina/orchestrators.py` | Every architectural condition and ablation; DelegationGraph executor; metrics per case |
| `experiments/run.py` | Experiment definitions (seeds, cases, scales, fault rates) and driver |
| `analysis/analyze.py` | Statistics (seed-level 95% t-intervals, exact McNemar), tables, figures |

## Deployment measured

The harness runs four service processes plus one driver process. The processes talk JSON over
HTTP/1.1 keep-alive on the loopback interface, with `TCP_NODELAY` set:

1. intent + synthesis
2. SIEM backends (primary, replica, and the 11 variants)
3. EDR backends (primary and replica)
4. correlators (primary and the lite fallback)

The driver hosts the coordination logic and is the only caller, so it counts every byte that
crosses a service boundary, retries included. Latency is wall-clock time from request to answer,
measured in the driver.

## What is modeled, not measured

- **Backends are deterministic, rule-based retrieval and reasoning services, not LLMs.**
  Absolute latencies are therefore milliseconds. In a deployment with model inference, the
  same absolute contract overhead would be a much smaller relative overhead.
- **Interpretation drift in the No-IntentFrame ablation is an explicit assumption.**
  Services on different release trains interpret raw requests with different parser versions
  (see `intent.py` and `services.build_catalog`). The `no_if_nodrift` condition removes the
  drift, which isolates its effect.
- **Integration effort for Experiment B is analytic.** It counts the consumer-side code
  locations whose interface assumptions a variant violates, using the `TOUCHPOINTS` table in
  `orchestrators.py`; each location is marked `TOUCHPOINT` in the source. The analysis checks
  this count against the dynamic swap outcome.
