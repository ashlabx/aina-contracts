"""Experiment driver.

  python experiments/run.py all            # every experiment (about 15-25 min on 2 cores)
  python experiments/run.py nominal|scale|swap|faults [--seeds 1,2,3,4,5]

Raw per-case rows are written to results/raw/<experiment>.jsonl; the run configuration and
machine description to results/raw/<experiment>.config.json and results/environment.json.

Design notes
  * Seeds are independent repetitions: each seed draws a fresh workload sample and a fresh
    fault schedule. Within a seed, all conditions see identical cases and identical faults.
  * For each case, all conditions run back-to-back in a freshly shuffled order, after a
    'prime' call that loads the case's telemetry into the backends, so no condition pays a
    cold-cache penalty and slow drift in machine state affects all conditions equally.
  * The first WARMUP cases of every seed are executed but not recorded.
"""
import argparse
import json
import os
import platform
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aina import variants as V  # noqa: E402
from aina.orchestrators import run_case  # noqa: E402
from aina.transport import Cluster  # noqa: E402
from aina.workload import make_case  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results", "raw")
SEEDS = [1, 2, 3, 4, 5]
WARMUP = 10

EXPERIMENTS = {
    "nominal": dict(scales=[640], cases=200, rates=[0.0], deadline_ms=5000, timeout_sleep_ms=0,
                    conditions=["full", "slim", "adhoc", "adhoc_inline", "no_if", "no_if_nodrift", "no_eb", "no_dg"]),
    "scale": dict(scales=[160, 320, 640, 1280, 2560, 5120, 10240], cases=100, rates=[0.0], deadline_ms=5000,
                  timeout_sleep_ms=0, conditions=["full", "slim", "adhoc"]),
    "swap": dict(scales=[640], cases=100, rates=[0.0], deadline_ms=5000, timeout_sleep_ms=0,
                 conditions=["full", "no_eb", "no_dg", "no_if", "adhoc"], variants=V.VARIANTS),
    "faults": dict(scales=[640], cases=200, rates=[0.0, 0.05, 0.10, 0.20, 0.30, 0.40], deadline_ms=60,
                   timeout_sleep_ms=150, conditions=["full", "full_nofallback", "adhoc", "adhoc_inline"],
                   ablation_rates=[0.0, 0.20], ablation_conditions=["no_eb", "no_dg", "no_if"]),
}


def environment():
    def sh(cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True).strip()
        except Exception:
            return None
    cpu = sh("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2") or sh("sysctl -n machdep.cpu.brand_string")
    mem = sh("grep MemTotal /proc/meminfo | awk '{print $2}'")
    return {"platform": platform.platform(), "python": sys.version.split()[0],
            "implementation": platform.python_implementation(), "cpu": cpu, "logical_cpus": os.cpu_count(),
            "mem_kb": int(mem) if mem else None, "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "transport": "HTTP/1.1 keep-alive over loopback, TCP_NODELAY, JSON bodies",
            "processes": "4 service processes (intent+synthesis | SIEM backends | EDR backends | correlators) + 1 driver"}


def prime(client, seed, case_id, scale):
    for svc in ("siem", "edr"):
        client.call(svc, "prime", b"{}", {"X-Case": "%d:%d:%d" % (seed, case_id, scale)}, 60)


def run_experiment(name, seeds, cluster):
    cfg = EXPERIMENTS[name]
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name + ".jsonl")
    with open(os.path.join(OUT, name + ".config.json"), "w") as f:
        json.dump(dict(cfg, seeds=seeds, warmup=WARMUP), f, indent=2)
    client = cluster.client()
    t0 = time.time()
    n = 0
    with open(path, "w") as out:
        for seed in seeds:
            order_rng = random.Random("order:%s:%s" % (name, seed))
            for scale in cfg["scales"]:
                for case_id in range(-WARMUP, cfg["cases"]):
                    cid = case_id if case_id >= 0 else 10_000 + case_id  # warm-up cases use distinct ids
                    case = make_case(seed, cid)
                    prime(client, seed, cid, scale)
                    jobs = []
                    for rate in cfg["rates"]:
                        for cond in cfg["conditions"]:
                            if name == "swap":
                                for v in cfg["variants"]:
                                    jobs.append((cond, rate, v))
                            else:
                                jobs.append((cond, rate, None))
                    if "ablation_conditions" in cfg:
                        for rate in cfg["ablation_rates"]:
                            for cond in cfg["ablation_conditions"]:
                                jobs.append((cond, rate, None))
                    order_rng.shuffle(jobs)
                    for cond, rate, variant in jobs:
                        slot = {"siem": "siem_" + variant} if variant else None
                        row = run_case(cond, client, case, scale, fault_rate=rate, deadline_ms=cfg["deadline_ms"],
                                       timeout_sleep_ms=cfg["timeout_sleep_ms"], slot=slot)
                        if variant:
                            row["variant"] = variant
                        if case_id >= 0:
                            out.write(json.dumps(row) + "\n")
                            n += 1
                print("[%s] seed=%d scale=%d done (%d rows, %.0fs)" % (name, seed, scale, n, time.time() - t0), flush=True)
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("experiment", choices=list(EXPERIMENTS) + ["all"])
    ap.add_argument("--seeds", default=",".join(map(str, SEEDS)))
    ap.add_argument("--port", type=int, default=18100)
    a = ap.parse_args()
    seeds = [int(s) for s in a.seeds.split(",")]
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(os.path.dirname(OUT), "environment.json"), "w") as f:
        json.dump(environment(), f, indent=2)
    names = list(EXPERIMENTS) if a.experiment == "all" else [a.experiment]
    with Cluster(a.port) as cl:
        for name in names:
            run_experiment(name, seeds, cl)


if __name__ == "__main__":
    main()
