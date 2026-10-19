"""Service implementations (intent, retrieval backends, correlators, synthesis) and the
transport-independent request dispatcher, including fault injection.

Each operation receives a JSON body and a control context (`ctl`) carried in HTTP headers that
are *not* counted as payload: the dataset handle (seed, case, scale), the fault schedule key,
and experiment switches. In a production deployment the dataset handle corresponds to the
backend's own data store.
"""
import hashlib
import json
from collections import OrderedDict

from . import contracts as C
from . import reasoning as R
from . import variants as V
from .faults import corrupt_structural, fault_for, truncate
from .intent import PARSERS, parse_v2
from .workload import case_records, make_case

# ------------------------------------------------------------------------ data access (cached)

_CASES = OrderedDict()
_RECS = OrderedDict()


def get_case(seed, case_id):
    k = (seed, case_id)
    if k not in _CASES:
        _CASES[k] = make_case(seed, case_id)
        if len(_CASES) > 4096:
            _CASES.popitem(last=False)
    return _CASES[k]


def get_records(seed, case_id, scale, source):
    k = (seed, case_id, scale)
    if k not in _RECS:
        _RECS[k] = case_records(get_case(seed, case_id), scale)
        while len(_RECS) > 6:
            _RECS.popitem(last=False)
    else:
        _RECS.move_to_end(k)
    return _RECS[k][source]


def _hid(*parts):
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:16]


# ------------------------------------------------------------------------ contract builders

def make_intent_frame(request_id, p, deadline_ms=5000):
    f = {
        "contract": "IntentFrame", "contract_version": C.CURRENT_VERSION["IntentFrame"],
        "frame_id": "if-" + _hid(request_id), "revision": 1, "goal": "host_investigation",
        "entities": [{"type": "host", "value": p["host"]}],
        "constraints": {"time_window": {"start": p["start"], "end": p["end"]},
                        "data_sources": ["siem", "edr"], "deadline_ms": int(deadline_ms)},
        "context_refs": ["request:%s" % request_id],
        "target_confidence": p["target"],
    }
    return f


def frame_host(f):
    return next(e["value"] for e in f["entities"] if e["type"] == "host")


def _item_from_rec(rec, source, producer):
    attrs = {k: v for k, v in rec.items() if k not in ("kind", "ts", "host", "rid")}
    return {"item_id": "%s:%s" % (producer, rec.get("rid", "?")), "source": source, "kind": rec["kind"],
            "ts": rec["ts"], "host": rec["host"], "attrs": attrs,
            "indicator_ids": [i for i, _, _ in R.indicators(rec)]}


def rec_from_item(item):
    rec = dict(item["attrs"])
    rec.update(kind=item["kind"], ts=item["ts"], host=item["host"], rid=item["item_id"].split(":", 1)[-1])
    return rec


def make_evidence_bundle(producer, source, adapter, frame_ref, query, as_is, version=None):
    hits = as_is["hits"]
    items = [_item_from_rec(h["rec"], source, producer) for h in hits]
    b = {
        "contract": "EvidenceBundle", "contract_version": version or C.CURRENT_VERSION["EvidenceBundle"],
        "bundle_id": "eb-" + _hid(producer, frame_ref, len(items)), "frame_ref": frame_ref,
        "producer": producer, "query": query, "status": "ok" if items else "empty",
        "evidence_items": items,
        "provenance": {"backend": producer, "adapter": adapter, "record_ids": [h["rec"].get("rid", "?") for h in hits]},
        "salience": [min(1.0, round(h["score"] / 6.0, 4)) for h in hits],
        "notes": {},
    }
    return b


def evolve_bundle(b, version):
    """Contract-evolution test hook. 1.1 = additive optional field; 2.0 = breaking rename."""
    if version == "1.1":
        b["contract_version"] = "1.1"
        b["time_scope"] = {"start": min((i["ts"] for i in b["evidence_items"]), default=0),
                           "end": max((i["ts"] for i in b["evidence_items"]), default=0)}
    elif version == "2.0":
        b["contract_version"] = "2.0"
        b["items"] = b.pop("evidence_items")
    return b


# ------------------------------------------------------------------------ services

class IntentService:
    caps = {"normalize_intent"}

    def call(self, op, body, ctl):
        if op == "normalize":
            p = parse_v2(body["request"])
            if p is None:
                return {"error": "unresolvable_intent", "reason": "no resolvable host entity"}
            f = make_intent_frame(body["request_id"], p, body.get("deadline_ms", 5000))
            C.validate("IntentFrame", f, producer="intent")  # I1: only valid frames are released
            return f
        if op == "refine":
            # Typed feedback signal from the coordination layer (RefineRequest). The intent layer
            # alone decides how the frame changes and issues a new, re-validated revision.
            f = dict(body["frame"])
            f["constraints"] = json.loads(json.dumps(f["constraints"]))
            if body.get("suggestion") == "widen_time_window":
                tw = f["constraints"]["time_window"]
                tw["start"] = max(0, tw["end"] - 2 * (tw["end"] - tw["start"]))
            f["revision"] = f["revision"] + 1
            C.validate("IntentFrame", f, producer="intent")
            return f
        if op == "normalize_slim":
            p = parse_v2(body["request"])
            return p if p is not None else {"error": "unresolvable_intent"}
        raise KeyError("unknown op " + op)


class RetrievalService:
    def __init__(self, name, source, variant, parser="v2"):
        self.name, self.source, self.variant, self.parser = name, source, variant, parser
        self.caps = {"retrieve_" + source}

    def _hits(self, ctl, host, start, end):
        if ctl.get("empty"):
            return [], []
        recs = get_records(ctl["seed"], ctl["case_id"], ctl["scale"], self.source)
        if self.variant == "all_matches":
            am = R.all_matches(recs, host, start, end)
            return R.rank(am), am
        return R.retrieve(recs, host, start, end), None

    def _bundle(self, ctl, frame_ref, host, start, end, version=None):
        hits, allh = self._hits(ctl, host, start, end)
        native = V.produce(self.variant, hits, allh)
        as_is = V.NORMALIZE[self.variant](native)  # producer-side adapter
        q = {"host": host, "start": start, "end": end}
        b = make_evidence_bundle(self.name, self.source, "adapter:" + self.variant, frame_ref, q, as_is)
        return evolve_bundle(b, version) if version else b

    def call(self, op, body, ctl):
        if op == "prime":
            get_records(ctl["seed"], ctl["case_id"], ctl["scale"], self.source)
            return {"ok": True}
        if op == "retrieve":
            f = body["frame"]
            tw = f["constraints"]["time_window"]
            return self._bundle(ctl, f["frame_id"], frame_host(f), tw["start"], tw["end"], body.get("emit_version"))
        if op == "retrieve_raw":
            parser = "v2" if ctl.get("nodrift") else self.parser
            p = PARSERS[parser](body["request"]) or {"host": None, "start": 0, "end": 1}
            return self._bundle(ctl, body["request_id"], p["host"], p["start"], p["end"])
        if op == "retrieve_slim":
            i = body["intent"]
            hits, _ = self._hits(ctl, i["host"], i["start"], i["end"])
            items = []
            for r, s in hits:
                d = dict(r)
                d["score"] = s
                items.append(d)
            return {"source": self.source, "items": items}
        if op == V.OP_NAME[self.variant]:
            hits, allh = self._hits(ctl, body["host"], body["start"], body["end"])
            return V.produce(self.variant, hits, allh)
        raise KeyError("unknown op %s for %s" % (op, self.name))


class CorrelatorService:
    def __init__(self, name, lite, parser="v2"):
        self.name, self.lite, self.parser = name, lite, parser
        self.caps = {"correlate"}

    def _eb(self, frame_ref, host, scores, present, ctl):
        if ctl.get("empty"):
            items, notes = [], {}
        else:
            items = [{"item_id": "%s:summary" % self.name, "source": "derived", "kind": "correlation_summary",
                      "ts": 0, "host": host or "", "attrs": {"category_scores": scores, "sources_present": present},
                      "indicator_ids": []}]
            notes = {"category_scores": scores, "sources_present": present}
        return {"contract": "EvidenceBundle", "contract_version": "1.0", "bundle_id": "eb-" + _hid(self.name, frame_ref),
                "frame_ref": frame_ref, "producer": self.name, "query": {"host": host},
                "status": "ok" if items else "empty", "evidence_items": items,
                "provenance": {"backend": self.name, "adapter": "native", "record_ids": []},
                "salience": [1.0] * len(items), "notes": notes}

    def _from_bundles(self, bundles, host):
        by_src = {}
        for b in bundles:
            if b["status"] != "ok":
                continue
            by_src.setdefault(b["evidence_items"][0]["source"], []).extend(rec_from_item(i) for i in b["evidence_items"])
        return R.correlate(by_src, host, self.lite)

    def call(self, op, body, ctl):
        if op == "correlate":
            f = body["frame"]
            host = frame_host(f)
            scores, present = self._from_bundles(body["bundles"], host)
            return self._eb(f["frame_id"], host, scores, present, ctl)
        if op == "correlate_raw":
            parser = "v2" if ctl.get("nodrift") else self.parser
            p = PARSERS[parser](body["request"]) or {"host": None}
            scores, present = self._from_bundles(body["bundles"], p["host"])
            return self._eb(body["request_id"], p["host"], scores, present, ctl)
        if op == "correlate_slim":
            by_src = {e["source"]: e["items"] for e in body["evidence"] if e["items"]}
            scores, present = R.correlate(by_src, body["intent"]["host"], self.lite)
            if ctl.get("empty"):
                return {"scores": {}, "sources_present": []}
            return {"scores": scores, "sources_present": present}
        if op == "correlate_native":
            # Consumes backend-native result lists (ad hoc and No-EvidenceBundle designs).
            by_src = {}
            for src, hits in body["hits"].items():
                if hits:
                    by_src[src] = [h["rec"] for h in hits]          # TOUCHPOINT correlator.native_iter
            scores, present = R.correlate(by_src, body["host"], self.lite)  # TOUCHPOINT correlator.record_fields
            if ctl.get("empty"):
                return {"scores": {}, "sources_present": []}
            return {"scores": scores, "sources_present": present}
        raise KeyError("unknown op " + op)


class SynthesisService:
    caps = {"synthesize"}

    def __init__(self, parser="v2"):
        self.parser = parser

    def call(self, op, body, ctl):
        if op == "synthesize":
            c = body["correlation"]
            a = R.synthesize(c["notes"]["category_scores"], c["notes"]["sources_present"], body["frame"]["target_confidence"])
            a["frame_ref"] = body["frame"]["frame_id"]
            a["evidence_refs"] = [c["bundle_id"]]
            return a
        if op == "synthesize_raw":
            parser = "v2" if ctl.get("nodrift") else self.parser
            p = PARSERS[parser](body["request"]) or {"target": 0.6}
            c = body["correlation"]
            return R.synthesize(c["notes"]["category_scores"], c["notes"]["sources_present"], p["target"])
        if op == "synthesize_slim":
            c = body["correlation"]
            return R.synthesize(c["scores"], c["sources_present"], body["intent"]["target"])
        if op == "synthesize_native":
            return R.synthesize(body["scores"], body["sources_present"], body["target"])
        raise KeyError("unknown op " + op)


# ------------------------------------------------------------------------ catalog

def build_catalog():
    """All services. In No-IntentFrame runs, components interpret the raw request with the parser
    version listed here (siem, siem_replica, correlator: v1; others: v2) unless nodrift is set."""
    cat = {
        "intent": IntentService(),
        "siem": RetrievalService("siem", "siem", "as_is", parser="v1"),
        "edr": RetrievalService("edr", "edr", "as_is", parser="v2"),
        "siem_replica": RetrievalService("siem_replica", "siem", "docs_relevance", parser="v1"),
        "edr_replica": RetrievalService("edr_replica", "edr", "nested_ret", parser="v2"),
        "correlator": CorrelatorService("correlator", lite=False, parser="v1"),
        "correlator_lite": CorrelatorService("correlator_lite", lite=True, parser="v2"),
        "synthesis": SynthesisService(parser="v2"),
    }
    for v in V.VARIANTS:
        cat["siem_" + v] = RetrievalService("siem_" + v, "siem", v, parser="v1")
    return cat


PROCESS_GROUPS = {
    "p_intent_synth": ["intent", "synthesis"],
    "p_siem": ["siem", "siem_replica"] + ["siem_" + v for v in V.VARIANTS],
    "p_edr": ["edr", "edr_replica"],
    "p_reason": ["correlator", "correlator_lite"],
}


def registry():
    """service -> capabilities (used to validate DelegationGraph bindings, invariant I3)."""
    return {n: s.caps for n, s in build_catalog().items()}


# ------------------------------------------------------------------------ dispatcher

def parse_ctl(headers):
    seed, case_id, scale = headers.get("X-Case", "0:0:0").split(":")
    rate, attempt = headers.get("X-Fault", "0|1").split("|")
    return {"seed": int(seed), "case_id": int(case_id), "scale": int(scale), "rate": float(rate),
            "attempt": int(attempt), "nodrift": headers.get("X-NoDrift") == "1",
            "timeout_sleep_ms": int(headers.get("X-Timeout-Sleep-Ms", "0"))}


def handle(catalog, service, op, raw_body, headers):
    """Returns (status, response_bytes, sleep_seconds)."""
    ctl = parse_ctl(headers)
    if op == "ping":
        return 200, b'{"ok":true}', 0.0
    fault = fault_for(ctl["seed"], ctl["case_id"], service, ctl["attempt"], ctl["rate"])
    kind, sub = fault if fault else (None, None)
    ctl["empty"] = kind == "empty"
    try:
        body = json.loads(raw_body) if raw_body else {}
        obj = catalog[service].call(op, body, ctl)
    except Exception as e:  # service-side failure -> HTTP 500
        return 500, json.dumps({"error": type(e).__name__, "detail": str(e)[:200]}).encode(), 0.0
    if kind == "malformed" and sub == "structural":
        # corrupt a deep copy: the response may reference cached telemetry records
        obj = json.loads(json.dumps(obj))
        corrupt_structural(obj, "%s|%s|%s|%s" % (ctl["seed"], ctl["case_id"], service, ctl["attempt"]))
    raw = json.dumps(obj, separators=(",", ":")).encode()
    if kind == "malformed" and sub == "truncated":
        raw = truncate(raw)
    sleep = ctl["timeout_sleep_ms"] / 1000.0 if kind == "timeout" else 0.0
    return 200, raw, sleep
