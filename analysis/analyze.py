"""Turn raw per-case rows into tables, figures and a summary.

  python analysis/analyze.py

Statistics
  * Unit of replication = seed (independent workload sample + fault schedule), n = 5.
    Reported as mean across seeds with a 95% t-interval (t_{0.975,4} = 2.776).
  * Latency: p50/p95 computed per seed over that seed's cases, then averaged across seeds.
    Overhead of A vs B = per-seed (p50_A / p50_B - 1), then mean and 95% t-interval.
  * Paired accuracy comparisons: exact McNemar test on pooled case-level outcomes.
"""
import json
import math
import os
import sys
from collections import defaultdict

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from aina import variants as V  # noqa: E402
from aina.orchestrators import TOUCHPOINTS, integration_effort  # noqa: E402

RAW = os.path.join(ROOT, "results", "raw")
TAB = os.path.join(ROOT, "results", "tables")
FIG = os.path.join(ROOT, "results", "figures")
T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}


def load(name):
    """Read raw rows from results/raw/<name>.jsonl, or the compressed .jsonl.gz shipped in the repository."""
    import gzip
    p = os.path.join(RAW, name + ".jsonl")
    if os.path.exists(p):
        with open(p) as f:
            return [json.loads(l) for l in f]
    if os.path.exists(p + ".gz"):
        with gzip.open(p + ".gz", "rt") as f:
            return [json.loads(l) for l in f]
    return []


def tci(vals):
    v = np.asarray(vals, dtype=float)
    n = len(v)
    m = float(v.mean())
    if n < 2:
        return m, float("nan"), float("nan")
    h = T975.get(n - 1, 1.96) * float(v.std(ddof=1)) / math.sqrt(n)
    return m, m - h, m + h


def fmt(m, lo, hi, d=3, pct=False):
    if pct:  # proportions: clip the interval to [0, 1] for display
        lo, hi = max(0.0, lo), min(1.0, hi)
        return "%.1f%% [%.1f, %.1f]" % (100 * m, 100 * lo, 100 * hi)
    return ("%." + str(d) + "f [%." + str(d) + "f, %." + str(d) + "f]") % (m, lo, hi)


def mcnemar(a, b):
    """Exact two-sided McNemar p-value. a, b: lists of booleans (paired)."""
    n01 = sum(1 for x, y in zip(a, b) if x and not y)
    n10 = sum(1 for x, y in zip(a, b) if y and not x)
    n = n01 + n10
    if n == 0:
        return 1.0, n01, n10
    k = min(n01, n10)
    p = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return min(1.0, 2 * p), n01, n10


def by(rows, *keys):
    out = defaultdict(list)
    for r in rows:
        out[tuple(r[k] for k in keys)].append(r)
    return out


def write_csv(name, header, rows):
    os.makedirs(TAB, exist_ok=True)
    with open(os.path.join(TAB, name + ".csv"), "w") as f:
        f.write(",".join(header) + "\n")
        for r in rows:
            f.write(",".join('"%s"' % x if isinstance(x, str) and "," in x else str(x) for x in r) + "\n")


def md_table(header, rows):
    s = "| " + " | ".join(header) + " |\n|" + "---|" * len(header) + "\n"
    for r in rows:
        s += "| " + " | ".join(str(x) for x in r) + " |\n"
    return s


SUMMARY = {}
REPORT = []


# =================================================================================== nominal

def nominal():
    rows = load("nominal")
    if not rows:
        return
    g = by(rows, "condition", "seed")
    conds = ["full", "slim", "adhoc", "adhoc_inline", "no_if", "no_if_nodrift", "no_eb", "no_dg"]
    seeds = sorted({r["seed"] for r in rows})
    stat = {}
    for c in conds:
        per = [g[(c, s)] for s in seeds]
        stat[c] = {
            "p50": tci([np.percentile([r["latency_ms"] for r in p], 50) for p in per]),
            "p95": tci([np.percentile([r["latency_ms"] for r in p], 95) for p in per]),
            "bytes": tci([np.mean([r["bytes"] for r in p]) for p in per]),
            "acc": tci([np.mean([r["correct"] for r in p]) for p in per]),
            "usable": tci([np.mean([r["usable"] for r in p]) for p in per]),
            "valid_ms": tci([np.mean([r["validation_ms"] for r in p]) for p in per]),
            "calls": tci([np.mean([r["n_calls"] for r in p]) for p in per]),
            "exec_invalid": sum(r["executed_invalid"] for p in per for r in p),
            "n_invalid": sum(r["invalid"] for p in per for r in p),
            "n": sum(len(p) for p in per),
        }

    def overhead(a, b, key="latency_ms", q=50):
        vals = []
        for s in seeds:
            pa = np.percentile([r[key] for r in g[(a, s)]], q)
            pb = np.percentile([r[key] for r in g[(b, s)]], q)
            vals.append(pa / pb - 1)
        return tci(vals)

    def bytes_over(a, b):
        return tci([np.mean([r["bytes"] for r in g[(a, s)]]) / np.mean([r["bytes"] for r in g[(b, s)]]) - 1 for s in seeds])

    ov = {"full_vs_slim_p50": overhead("full", "slim"), "full_vs_slim_p95": overhead("full", "slim", q=95),
          "full_vs_adhoc_p50": overhead("full", "adhoc"), "full_vs_slim_bytes": bytes_over("full", "slim"),
          "full_vs_adhoc_bytes": bytes_over("full", "adhoc")}
    # validation share of the full-vs-slim latency gap
    gap = stat["full"]["p50"][0] - stat["slim"]["p50"][0]
    vshare = (stat["full"]["valid_ms"][0] - stat["slim"]["valid_ms"][0]) / gap if gap > 0 else float("nan")

    key = lambda r: (r["seed"], r["case_id"])
    idx = {c: {key(r): r for r in rows if r["condition"] == c} for c in conds}
    tests = {}
    for a, b in [("full", "adhoc"), ("full", "slim"), ("full", "no_if"), ("full", "no_if_nodrift"), ("no_if", "no_if_nodrift")]:
        ks = sorted(idx[a])
        tests[a + "_vs_" + b] = mcnemar([idx[a][k]["correct"] for k in ks], [idx[b][k]["correct"] for k in ks])

    hdr = ["condition", "p50 latency ms", "p95 latency ms", "mean bytes/case", "task accuracy", "usable-answer rate",
           "driver validation ms", "calls/case", "invalid requests executed"]
    trs = []
    for c in conds:
        s = stat[c]
        trs.append([c, fmt(*s["p50"], d=2), fmt(*s["p95"], d=2), fmt(*s["bytes"], d=0), fmt(*s["acc"]),
                    fmt(*s["usable"]), fmt(*s["valid_ms"], d=2), "%.2f" % s["calls"][0],
                    "%d / %d" % (s["exec_invalid"], s["n_invalid"])])
    write_csv("table_nominal", hdr, trs)
    REPORT.append("## RQ1 - Nominal overhead (scale 640 records/case, no faults)\n\n"
                  "n = %d cases per condition (5 seeds x 200). Values: mean across seeds [95%% CI].\n\n" % stat["full"]["n"]
                  + md_table(hdr, trs)
                  + "\nOverheads (per-seed ratio, mean [95%% CI]): full vs slim p50 **%s**, p95 %s; full vs ad hoc p50 %s; "
                    "bytes full vs slim %s, full vs ad hoc %s.\n\nValidation accounts for %.0f%% of the full-vs-slim p50 gap.\n\n"
                  % (fmt(*ov["full_vs_slim_p50"], pct=True), fmt(*ov["full_vs_slim_p95"], pct=True),
                     fmt(*ov["full_vs_adhoc_p50"], pct=True), fmt(*ov["full_vs_slim_bytes"], pct=True),
                     fmt(*ov["full_vs_adhoc_bytes"], pct=True), 100 * vshare)
                  + "Paired accuracy tests (exact McNemar; n01 = only first correct, n10 = only second correct):\n\n"
                  + "\n".join("- %s: p = %.3g (n01=%d, n10=%d)" % (k, *v) for k, v in tests.items()) + "\n")
    SUMMARY["nominal"] = {"stats": stat, "overheads": ov, "validation_share_of_gap": vshare, "mcnemar": tests}


# =================================================================================== scale

def scale():
    rows = load("scale")
    if not rows:
        return
    g = by(rows, "condition", "scale", "seed")
    conds = ["full", "slim", "adhoc"]
    scales = sorted({r["scale"] for r in rows})
    seeds = sorted({r["seed"] for r in rows})
    res = {}
    for c in conds:
        for sc in scales:
            res[(c, sc)] = {
                "p50": tci([np.percentile([r["latency_ms"] for r in g[(c, sc, s)]], 50) for s in seeds]),
                "bytes": tci([np.mean([r["bytes"] for r in g[(c, sc, s)]]) for s in seeds]),
                "acc": tci([np.mean([r["correct"] for r in g[(c, sc, s)]]) for s in seeds]),
            }
    ovs = {}
    for sc in scales:
        ovs[sc] = tci([np.percentile([r["latency_ms"] for r in g[("full", sc, s)]], 50) /
                       np.percentile([r["latency_ms"] for r in g[("slim", sc, s)]], 50) - 1 for s in seeds])
    # average over scales: per seed, mean of per-scale overheads
    avg = tci([np.mean([np.percentile([r["latency_ms"] for r in g[("full", sc, s)]], 50) /
                        np.percentile([r["latency_ms"] for r in g[("slim", sc, s)]], 50) - 1 for sc in scales]) for s in seeds])
    absdiff = {sc: tci([np.percentile([r["latency_ms"] for r in g[("full", sc, s)]], 50) -
                        np.percentile([r["latency_ms"] for r in g[("slim", sc, s)]], 50) for s in seeds]) for sc in scales}
    bover = tci([np.mean([np.mean([r["bytes"] for r in g[("full", sc, s)]]) / np.mean([r["bytes"] for r in g[("slim", sc, s)]]) - 1
                          for sc in scales]) for s in seeds])
    hdr = ["records/case"] + ["%s p50 ms" % c for c in conds] + ["full-slim p50 diff ms", "full vs slim p50 overhead"] + \
          ["%s bytes" % c for c in conds] + ["accuracy (full)"]
    trs = []
    for sc in scales:
        trs.append([sc] + [fmt(*res[(c, sc)]["p50"], d=2) for c in conds] + [fmt(*absdiff[sc], d=2), fmt(*ovs[sc], pct=True)] +
                   ["%.0f" % res[(c, sc)]["bytes"][0] for c in conds] + ["%.3f" % res[("full", sc)]["acc"][0]])
    write_csv("table_scale", hdr, trs)
    REPORT.append("## RQ2 - Scale sensitivity (no faults)\n\nn = %d cases per cell (5 seeds x %d).\n\n"
                  % (len(g[("full", scales[0], seeds[0])]) * len(seeds), len(g[("full", scales[0], seeds[0])]))
                  + md_table(hdr, trs)
                  + "\nAverage over the %d scales: full vs slim p50 overhead %s; bytes %s.\n\n"
                  % (len(scales), fmt(*avg, pct=True), fmt(*bover, pct=True)))
    SUMMARY["scale"] = {"cells": {"%s@%d" % k: v for k, v in res.items()}, "overhead_by_scale": ovs,
                        "overhead_avg": avg, "absdiff_ms": absdiff, "bytes_overhead_avg": bover}
    return res, scales, conds


# =================================================================================== swap

def swap():
    rows = load("swap")
    if not rows:
        return
    designs = [d for d in ["full", "no_dg", "no_if", "no_eb", "adhoc"] if any(r["condition"] == d for r in rows)]
    seeds = sorted({r["seed"] for r in rows})
    g = by(rows, "condition", "variant", "seed")
    out = {}
    for d in designs:
        for v in V.VARIANTS:
            ok = 0
            detail = []
            for s in seeds:
                ref = {r["case_id"]: r for r in g[(d, "as_is", s)]}
                rs = g[(d, v, s)]
                failed = sum(r["status"] == "failed" for r in rs)
                same = np.mean([(r["status"], r["verdict"], r["answer_category"]) ==
                                (ref[r["case_id"]]["status"], ref[r["case_id"]]["verdict"], ref[r["case_id"]]["answer_category"])
                                for r in rs])
                acc = np.mean([r["correct"] for r in rs])
                incompat = sum(r.get("slot_incompat", 0) for r in rs)
                success = failed == 0 and same >= 0.98 and incompat == 0
                ok += success
                detail.append({"seed": s, "failed": failed, "slot_incompat": incompat, "agreement": float(same), "accuracy": float(acc), "success": success})
            out[(d, v)] = {"success_seeds": ok, "n_seeds": len(seeds), "detail": detail}
    eff = {d: {v: integration_effort(d if d in TOUCHPOINTS else "full", v) for v in V.VARIANTS} for d in ["full", "no_eb", "adhoc"]}
    hdr = ["variant", "aspects changed"] + ["%s swap success (seeds)" % d for d in designs] + \
          ["ad hoc consumer edits", "no_eb consumer edits", "layered consumer edits", "layered producer adapter (LOC)"]
    trs = []
    for v in V.VARIANTS:
        trs.append([v, " ".join(sorted(V.ASPECTS[v])) or "-"] +
                   ["%d/%d" % (out[(d, v)]["success_seeds"], out[(d, v)]["n_seeds"]) for d in designs] +
                   [eff["adhoc"][v], eff["no_eb"][v], 0, V.adapter_loc(v)])
    rate = {d: sum(out[(d, v)]["success_seeds"] == out[(d, v)]["n_seeds"] for v in V.VARIANTS) / len(V.VARIANTS) for d in designs}
    med = {d: float(np.median([eff[d][v] for v in V.VARIANTS if v != "as_is"])) for d in eff}
    mean = {d: float(np.mean([eff[d][v] for v in V.VARIANTS if v != "as_is"])) for d in eff}
    # consistency: analytic effort > 0  <=>  dynamic swap failure
    consistency = {}
    for d in ["adhoc", "no_eb"]:
        if d in designs:
            consistency[d] = all((eff[d][v] > 0) == (out[(d, v)]["success_seeds"] == 0) for v in V.VARIANTS)
    write_csv("table_swap", hdr, trs)
    REPORT.append("## RQ3 - Heterogeneous backend substitutability (scale 640, no faults)\n\n"
                  "A swap succeeds for a seed if all 100 cases complete, >= 98% of answers equal the same design's answers "
                  "with the reference (as_is) backend, and no interface failure (malformed/error) is recorded against the swapped "
                  "backend (so a fallback replica cannot mask an incompatible backend). Consumer edits = consumer-side code locations whose assumptions "
                  "the variant violates (dependency table in orchestrators.TOUCHPOINTS).\n\n"
                  + md_table(hdr, trs)
                  + "\nZero-edit swap success (variants succeeding on all seeds / 11): "
                  + ", ".join("%s %d/11 (%.1f%%)" % (d, round(rate[d] * 11), 100 * rate[d]) for d in designs)
                  + ".\n\nConsumer-side edit locations per non-reference variant: median "
                  + ", ".join("%s %.1f" % (d, med[d]) for d in med) + "; mean "
                  + ", ".join("%s %.2f" % (d, mean[d]) for d in mean)
                  + ".\n\nAnalytic edit count agrees with dynamic outcome (effort>0 iff swap fails): "
                  + ", ".join("%s %s" % kv for kv in consistency.items()) + ".\n\n")
    SUMMARY["swap"] = {"by_design_variant": {"%s/%s" % k: v for k, v in out.items()}, "success_rate": rate,
                       "effort": eff, "effort_median": med, "effort_mean": mean, "consistency": consistency,
                       "adapter_loc": {v: V.adapter_loc(v) for v in V.VARIANTS}}
    return out, designs


# =================================================================================== faults

FK = ["timeout", "malformed_truncated", "malformed_structural", "empty"]


def faults():
    rows = load("faults")
    if not rows:
        return
    seeds = sorted({r["seed"] for r in rows})
    conds = [c for c in ["full", "full_nofallback", "adhoc", "adhoc_inline", "no_dg", "no_eb", "no_if"] if any(r["condition"] == c for r in rows)]
    base = {(r["condition"], r["seed"], r["case_id"]): r for r in rows if r["fault_rate"] == 0.0}
    g = by(rows, "condition", "fault_rate", "seed")
    rates = sorted({r["fault_rate"] for r in rows})
    res = {}
    for c in conds:
        for fr in rates:
            if not g.get((c, fr, seeds[0])):
                continue
            ret, loc, acc, use, fail, p50, calls, kinds, lk = [], [], [], [], [], [], [], defaultdict(int), defaultdict(int)
            for s in seeds:
                rs = g[(c, fr, s)]
                den = num = 0
                for r in rs:
                    b = base[(c, s, r["case_id"])]
                    if r["invalid"] or not b["usable"]:
                        continue
                    den += 1
                    num += r["usable"] and (r["verdict"], r["answer_category"]) == (b["verdict"], b["answer_category"])
                ret.append(num / den)
                f = sum(r["faults"] for r in rs)
                loc.append(sum(r["faults_localized"] for r in rs) / f if f else float("nan"))
                acc.append(np.mean([r["correct"] for r in rs]))
                use.append(np.mean([r["usable"] for r in rs]))
                fail.append(np.mean([r["status"] == "failed" for r in rs]))
                p50.append(np.percentile([r["latency_ms"] for r in rs], 50))
                calls.append(np.mean([r["n_calls"] for r in rs]))
                for r in rs:
                    for k, n in r["faults_by_kind"].items():
                        kinds[k] += n
                    for k, n in r["localized_by_kind"].items():
                        lk[k] += n
            res[(c, fr)] = {"retention": tci(ret), "localization": tci(loc) if fr > 0 else (float("nan"),) * 3,
                            "accuracy": tci(acc), "usable": tci(use), "failed": tci(fail), "p50": tci(p50),
                            "calls": tci(calls), "faults_by_kind": dict(kinds), "localized_by_kind": dict(lk),
                            "spurious_timeouts": sum(r["spurious_timeouts"] for s in seeds for r in g[(c, fr, s)]),
                            "error_components": dict(_count(r["error_component"] for s in seeds for r in g[(c, fr, s)] if r["error_component"]))}
    hdr = ["condition", "fault rate", "confidence retention", "failure localization", "task accuracy", "usable rate",
           "requests failed", "p50 latency ms", "calls/case"]
    trs = []
    for (c, fr), v in sorted(res.items(), key=lambda kv: (conds.index(kv[0][0]), kv[0][1])):
        trs.append([c, "%.0f%%" % (100 * fr), fmt(*v["retention"], pct=True),
                    "-" if fr == 0 else fmt(*v["localization"], pct=True), fmt(*v["accuracy"]), fmt(*v["usable"]),
                    fmt(*v["failed"], pct=True), fmt(*v["p50"], d=1), "%.2f" % v["calls"][0]])
    write_csv("table_faults", hdr, trs)
    # localization by fault kind at 30%
    lhdr = ["condition"] + ["%s (localized/injected)" % k for k in FK]
    ltr = []
    for c in conds:
        fr = 0.30 if (c, 0.30) in res else 0.20
        v = res[(c, fr)]
        ltr.append(["%s @%d%%" % (c, 100 * fr)] + ["%d/%d (%.0f%%)" % (v["localized_by_kind"].get(k, 0), v["faults_by_kind"].get(k, 0),
                                                                      100 * v["localized_by_kind"].get(k, 0) / max(1, v["faults_by_kind"].get(k, 0))) for k in FK])
    write_csv("table_localization_by_kind", lhdr, ltr)
    # paired contrasts (per-seed differences, same cases and fault schedule)
    def per_seed(c, fr, metric):
        vals = []
        for s in seeds:
            rs = g[(c, fr, s)]
            if metric == "retention":
                den = num = 0
                for r in rs:
                    b = base[(c, s, r["case_id"])]
                    if r["invalid"] or not b["usable"]:
                        continue
                    den += 1
                    num += r["usable"] and (r["verdict"], r["answer_category"]) == (b["verdict"], b["answer_category"])
                vals.append(num / den)
            else:
                vals.append(sum(r["faults_localized"] for r in rs) / sum(r["faults"] for r in rs))
        return np.array(vals)
    contrasts = {}
    chdr = ["contrast", "fault rate", "retention difference (pp)", "localization difference (pp)"]
    ctr = []
    for a, b2, frs in [("full", "adhoc", [0.2, 0.3]), ("full", "adhoc_inline", [0.2, 0.3]), ("full", "full_nofallback", [0.2, 0.3]),
                       ("adhoc_inline", "adhoc", [0.2, 0.3]), ("full", "no_dg", [0.2]), ("full", "no_eb", [0.2])]:
        for fr in frs:
            if (a, fr) not in res or (b2, fr) not in res:
                continue
            dr = tci(100 * (per_seed(a, fr, "retention") - per_seed(b2, fr, "retention")))
            dl = tci(100 * (per_seed(a, fr, "loc") - per_seed(b2, fr, "loc")))
            contrasts["%s-%s@%.2f" % (a, b2, fr)] = {"retention_pp": dr, "localization_pp": dl}
            ctr.append(["%s minus %s" % (a, b2), "%.0f%%" % (100 * fr), "%+.1f [%+.1f, %+.1f]" % dr, "%+.1f [%+.1f, %+.1f]" % dl])
    write_csv("table_fault_contrasts", chdr, ctr)
    spur = sum(v["spurious_timeouts"] for v in res.values())
    ncalls = sum(r["n_calls"] for r in rows)
    REPORT.append("## RQ4 - Mixed-fault stress (scale 640; per-call deadline 60 ms; injected timeouts sleep 150 ms)\n\n"
                  "Confidence retention = share of valid requests whose fault-free answer was usable that, under faults, still "
                  "return a usable answer with the same verdict and category. Failure localization = share of injected fault "
                  "events that the system's own error records attribute to the faulty service and call. n = 1000 cases per cell.\n\n"
                  + md_table(hdr, trs) + "\nLocalization by fault kind:\n\n" + md_table(lhdr, ltr)
                  + "\nPaired contrasts (per-seed differences, mean [95% CI], percentage points):\n\n" + md_table(chdr, ctr)
                  + "\nSpurious (non-injected) timeouts: %d of %d calls.\n\n" % (spur, ncalls))
    SUMMARY["faults"] = {"%s@%.2f" % k: v for k, v in res.items()}
    SUMMARY["fault_contrasts"] = contrasts
    return res, conds, rates


def _count(it):
    d = defaultdict(int)
    for x in it:
        d[x] += 1
    return d


# =================================================================================== ablation

def ablation():
    nom = SUMMARY.get("nominal", {}).get("stats", {})
    fl = SUMMARY.get("faults", {})
    sw = SUMMARY.get("swap", {})
    if not nom:
        return
    hdr = ["variant", "task accuracy", "usable rate", "invalid requests executed", "p50 latency ms", "bytes/case",
           "zero-edit swap success", "consumer edits/variant (median)", "confidence retention @20%", "localization @20%",
           "inspectable execution plan"]
    trs = []
    for c, label in [("full", "full design"), ("no_if", "no IntentFrame (drift)"), ("no_if_nodrift", "no IntentFrame (no drift)"),
                     ("no_eb", "no EvidenceBundle"), ("no_dg", "no DelegationGraph"), ("adhoc", "ad hoc baseline")]:
        s = nom[c]
        f = fl.get("%s@0.20" % c)
        swr = sw.get("success_rate", {}).get(c)
        effm = sw.get("effort_median", {}).get(c if c in ("full", "no_eb", "adhoc") else "full")
        trs.append([label, fmt(*s["acc"]), fmt(*s["usable"]), "%d / %d" % (s["exec_invalid"], s["n_invalid"]),
                    fmt(*s["p50"], d=2), "%.0f" % s["bytes"][0],
                    "-" if swr is None else "%d/11" % round(11 * swr), "-" if effm is None else "%.0f" % effm,
                    "-" if not f else fmt(*f["retention"], pct=True), "-" if not f else fmt(*f["localization"], pct=True),
                    "no" if c in ("no_dg", "adhoc") else "yes"])
    write_csv("table_ablation", hdr, trs)
    REPORT.append("## Ablation - all metrics per removed contract\n\n" + md_table(hdr, trs) +
                  "\n'Inspectable execution plan' is a structural property (the DelegationGraph and its per-node execution "
                  "state exist as data), not a measured effect.\n\n")


# =================================================================================== figures

def figures(sc, sw, fl):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    os.makedirs(FIG, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.spines.top": False,
                         "axes.spines.right": False, "axes.edgecolor": "#888", "axes.labelcolor": "#222",
                         "xtick.color": "#444", "ytick.color": "#444", "axes.grid": True, "grid.color": "#e6e6e6",
                         "grid.linewidth": 0.6, "legend.frameon": False, "savefig.dpi": 300})
    PAL = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
    MK = ["o", "s", "^", "D"]
    LS = ["-", "--", "-.", ":"]
    LABEL = {"full": "Full contracts", "slim": "Slim schema", "adhoc": "Ad hoc", "adhoc_inline": "Ad hoc + inline recovery",
             "full_nofallback": "Full contracts, no fallback", "no_eb": "No EvidenceBundle", "no_dg": "No DelegationGraph",
             "no_if": "No IntentFrame"}

    if sc:
        res, scales, conds = sc
        for metric, fname, ylab in [("p50", "fig3_latency_vs_scale", "p50 end-to-end latency (ms)"),
                                    ("bytes", "fig4_bytes_vs_scale", "Mean serialized bytes per request")]:
            fig, ax = plt.subplots(figsize=(6.0, 3.4))
            for i, c in enumerate(conds):
                m = [res[(c, s)][metric][0] for s in scales]
                lo = [res[(c, s)][metric][1] for s in scales]
                hi = [res[(c, s)][metric][2] for s in scales]
                ax.errorbar(scales, m, yerr=[np.subtract(m, lo), np.subtract(hi, m)], color=PAL[i], marker=MK[i],
                            ms=5, lw=2, ls=LS[i], capsize=2.5, label=LABEL[c])
            ax.set_xscale("log", base=2)
            ax.set_xticks(scales)
            ax.set_xticklabels([str(s) for s in scales])
            ax.set_xlabel("Telemetry records per case (log scale)")
            ax.set_ylabel(ylab)
            ax.set_ylim(bottom=0)
            if metric == "bytes":
                ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, _: "%dk" % (x / 1000)))
            ax.legend(loc="upper left" if metric == "p50" else "lower right")
            fig.tight_layout()
            fig.savefig(os.path.join(FIG, fname + ".png"))
            plt.close(fig)

    if sw:
        out, designs = sw
        ds = [d for d in ["adhoc", "no_eb", "full"] if d in designs]
        fig, ax = plt.subplots(figsize=(6.6, 3.2))
        x = np.arange(len(V.VARIANTS))
        w = 0.8 / len(ds)
        for i, d in enumerate(ds):
            vals = [100.0 * out[(d, v)]["success_seeds"] / out[(d, v)]["n_seeds"] for v in V.VARIANTS]
            ax.bar(x + (i - (len(ds) - 1) / 2) * w, vals, w * 0.88, color=[PAL[2], PAL[1], PAL[0]][i] if len(ds) == 3 else PAL[i],
                   label={"adhoc": "Ad hoc", "no_eb": "No EvidenceBundle", "full": "Full contracts"}[d], zorder=3)
        ax.set_xticks(x)
        ax.set_xticklabels(V.VARIANTS, rotation=35, ha="right")
        ax.set_ylabel("Zero-edit swap success (% of seeds)")
        ax.set_ylim(0, 122)
        ax.set_yticks([0, 20, 40, 60, 80, 100])
        ax.legend(loc="upper center", ncol=3)
        fig.tight_layout()
        fig.savefig(os.path.join(FIG, "fig5_swap_success.png"))
        plt.close(fig)

    if fl:
        res, conds, rates = fl
        cs = [c for c in ["full", "adhoc_inline", "full_nofallback", "adhoc"] if c in conds]
        for metric, fname, ylab in [("retention", "fig6_confidence_retention", "Confidence retention (%)"),
                                    ("localization", "fig7_failure_localization", "Failure localization (%)")]:
            fig, ax = plt.subplots(figsize=(6.0, 3.4))
            for i, c in enumerate(cs):
                rr = [r for r in rates if (c, r) in res and (metric == "retention" or r > 0)]
                m = [100 * res[(c, r)][metric][0] for r in rr]
                lo = [max(0.0, 100 * res[(c, r)][metric][1]) for r in rr]
                hi = [min(100.0, 100 * res[(c, r)][metric][2]) for r in rr]
                ax.errorbar([100 * r for r in rr], m, yerr=[np.subtract(m, lo), np.subtract(hi, m)], color=PAL[i], marker=MK[i],
                            ms=5, lw=2, ls=LS[i], capsize=2.5, label=LABEL[c])
            ax.set_xlabel("Injected fault rate per call (%)")
            ax.set_ylabel(ylab)
            ax.set_ylim(0, 102)
            if metric == "retention":
                ax.legend(loc="lower left")
            else:
                ax.legend(loc="center right", bbox_to_anchor=(1.0, 0.6))
            fig.tight_layout()
            fig.savefig(os.path.join(FIG, fname + ".png"))
            plt.close(fig)


def main():
    nominal()
    sc = scale()
    sw = swap()
    fl = faults()
    ablation()
    figures(sc, sw, fl)
    env = json.load(open(os.path.join(ROOT, "results", "environment.json")))
    head = ("# Re-executed experiments: results\n\nGenerated by analysis/analyze.py from results/raw/*.jsonl.\n\n"
            "Environment: %s; Python %s; %s logical CPUs; %s.\n\n" % (env["cpu"], env["python"], env["logical_cpus"], env["transport"]))
    with open(os.path.join(ROOT, "results", "RESULTS.md"), "w") as f:
        f.write(head + "\n".join(REPORT))

    def conv(o):
        if isinstance(o, dict):
            return {str(k): conv(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [conv(x) for x in o]
        if isinstance(o, (np.floating, np.integer)):
            return o.item()
        if isinstance(o, np.bool_):
            return bool(o)
        return o
    with open(os.path.join(ROOT, "results", "summary.json"), "w") as f:
        json.dump(conv(SUMMARY), f, indent=1)
    print("wrote results/RESULTS.md, results/summary.json, tables, figures")


if __name__ == "__main__":
    main()
