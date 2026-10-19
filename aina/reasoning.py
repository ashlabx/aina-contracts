"""Retrieval scoring, correlation and synthesis logic (pure functions, shared by all conditions).

All architectural conditions call exactly the same logic; they differ only in how state is
represented and exchanged at service boundaries. Any accuracy difference between conditions
therefore comes from the architecture (interpretation, data exchange, recovery), not from
different reasoning code.
"""
import math
from collections import defaultdict

from .workload import indicators

TOP_K = 25
THRESHOLD = 3.0
BASE_RELEVANCE = 0.01


def _score(r):
    # indicator weight plus a small base relevance, so a healthy backend always returns the
    # k most relevant (then most recent) records for the host/window; "empty" is an anomaly.
    return round(BASE_RELEVANCE + sum(w for _, _, w in indicators(r)), 4)


def retrieve(records, host, start, end, k=TOP_K):
    """Score records of one source for one host/time window. Returns [(rec, score)] sorted desc, top-k."""
    if host is None:
        return []
    hits = [(r, _score(r)) for r in records if r["host"] == host and start <= r["ts"] <= end]
    hits.sort(key=lambda x: (-x[1], -x[0]["ts"]))
    return hits[:k]


def all_matches(records, host, start, end):
    """Unranked, untruncated matches in time order (used by the 'all_matches' backend variant)."""
    if host is None:
        return []
    return [(r, _score(r)) for r in records if r["host"] == host and start <= r["ts"] <= end]


def rank(hits, k=TOP_K):
    hits = sorted(hits, key=lambda x: (-x[1], -x[0]["ts"]))
    return hits[:k]


def correlate(records_by_source, host, lite=False):
    """records_by_source: {'siem': [rec...], 'edr': [rec...]} (only sources that returned evidence).

    Returns (category_scores, sources_present). `lite` = fallback correlator: no beacon
    periodicity, no lateral-breadth, no cross-source corroboration bonus.
    """
    scores = defaultdict(float)
    src_of = defaultdict(set)
    flows = defaultdict(list)
    remote_dsts = set()
    for src, recs in records_by_source.items():
        for r in recs:
            for _, cat, w in indicators(r):
                scores[cat] += w
                src_of[cat].add(src)
            if r["kind"] == "flow":
                flows[r["dst_ip"]].append(r["ts"])
            if r["kind"] == "auth" and r.get("logon_type") == 3 and r.get("src_host") == host:
                remote_dsts.add(r.get("dst_host"))
    if not lite:
        for dst, ts in flows.items():
            if len(ts) >= 4:
                ts = sorted(ts)
                gaps = [b - a for a, b in zip(ts, ts[1:])]
                mean = sum(gaps) / len(gaps)
                sd = math.sqrt(sum((g - mean) ** 2 for g in gaps) / len(gaps))
                if mean > 0 and sd / mean < 0.15:
                    scores["c2_beaconing"] += 2.0
                    src_of["c2_beaconing"].add("siem")
        if len(remote_dsts) >= 3:
            scores["lateral_movement"] += 2.0
        for cat in list(scores):
            if len(src_of[cat]) >= 2:
                scores[cat] *= 1.25
    present = sorted(s for s, recs in records_by_source.items() if recs is not None)
    return {c: round(v, 4) for c, v in scores.items()}, present


def _sig(x):
    return 1.0 / (1.0 + math.exp(-x))


def synthesize(scores, sources_present, target, expected_sources=2):
    """Return answer dict: verdict, category, confidence, usable."""
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    top_cat, top = ranked[0] if ranked else (None, 0.0)
    second = ranked[1][1] if len(ranked) > 1 else 0.0
    completeness = min(1.0, len(sources_present) / float(expected_sources))
    if top >= THRESHOLD:
        verdict, category = "malicious", top_cat
        margin = (top - second) / top if top > 0 else 0.0
        conf = _sig((top - THRESHOLD) / 1.5 + 1.0) * (0.6 + 0.4 * margin)
    else:
        verdict, category = "benign", "benign"
        conf = _sig((THRESHOLD - top) / 1.0 + 0.5)
    conf *= (0.5 + 0.5 * completeness)
    conf = round(conf, 4)
    return {"verdict": verdict, "category": category, "confidence": conf, "usable": conf >= target}
