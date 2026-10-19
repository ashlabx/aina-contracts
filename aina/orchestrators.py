"""Architectural conditions.

  full             three layers, full contracts, validation at every boundary, DelegationGraph with
                   retry + fallback policy
  full_nofallback  as full, DelegationGraph policy max_attempts=1 and no alternates
  slim             same three hops, minimal payloads, key-presence checks only, no recovery
  adhoc            controller code: shared normalizer library, native backend calls, no
                   validation, no recovery (the original paper's ad hoc baseline)
  adhoc_inline     adhoc + the *same* retry/fallback policy as full, hard-coded inline
  no_if            ablation: no IntentFrame; each service interprets the raw request itself
                   (interpretation drift modeled by parser versions, see intent.py)
  no_if_nodrift    as no_if but every service uses the canonical parser (isolates drift)
  no_eb            ablation: no EvidenceBundle; backends return native payloads, consumers
                   contain backend-specific extraction code; DelegationGraph retained
  no_dg            ablation: no DelegationGraph; same retry/fallback policy hard-coded in the
                   controller; IntentFrame and EvidenceBundle retained

All conditions call identical reasoning code (reasoning.py).
"""
import json
import time
from collections import defaultdict

from . import contracts as C
from . import variants as V
from .faults import fault_for
from .intent import parse_v2
from .transport import CallError, CallTimeout

# Recovery policy shared by full, adhoc_inline and no_dg (identical parameters).
POLICY = {"max_attempts": 2, "backoff_ms": 2, "retry_on": ["timeout", "malformed", "empty", "error"]}
FALLBACK = {"siem": "siem_replica", "edr": "edr_replica", "correlator": "correlator_lite"}

# Consumer-side code locations that depend on a SIEM backend's interface aspects (integration
# effort, Experiment B). Each entry: design -> [(location, aspects it depends on)]. Locations are
# marked "TOUCHPOINT" in the source.
TOUCHPOINTS = {
    "adhoc": [("controller.siem_call", {"op_name"}),
              ("controller.siem_extract", {"container"}),
              ("correlator.native_iter", {"item_shape", "field_rec"}),
              ("correlator.record_fields", {"record_encoding"})],
    "no_eb": [("coordinator.extract[siem]", {"container"}),
              ("correlator.native_iter", {"item_shape", "field_rec"}),
              ("correlator.record_fields", {"record_encoding"})],
    "full": [],
}


def integration_effort(design, variant):
    asp = V.ASPECTS[variant]
    return sum(1 for _, deps in TOUCHPOINTS[design] if deps & asp)


class Failed(Exception):
    def __init__(self, component, reason):
        super().__init__("%s: %s" % (component, reason))
        self.component, self.reason = component, reason


class Ctx:
    def __init__(self, client, case, scale, fault_rate, deadline_ms, timeout_sleep_ms, nodrift=False):
        self.client, self.case, self.scale, self.rate = client, case, scale, fault_rate
        self.deadline_s = deadline_ms / 1000.0
        self.tsleep = timeout_sleep_ms
        self.nodrift = nodrift
        self.calls, self.detections, self.trace = [], [], []
        self.attempts = defaultdict(int)
        self.bytes = 0
        self.vtime = 0.0
        self.slot = {}   # logical backend slot -> service (for swap experiments)

    def svc(self, logical):
        return self.slot.get(logical, logical)

    def call(self, service, op, body):
        self.attempts[service] += 1
        a = self.attempts[service]
        cid = len(self.calls)
        self.calls.append({"cid": cid, "service": service, "op": op, "attempt": a,
                           "fault": fault_for(self.case["seed"], self.case["case_id"], service, a, self.rate),
                           "outcome": None})
        data = json.dumps(body, separators=(",", ":")).encode()
        self.bytes += len(data)
        hdr = {"X-Case": "%d:%d:%d" % (self.case["seed"], self.case["case_id"], self.scale),
               "X-Fault": "%s|%d" % (self.rate, a), "X-Timeout-Sleep-Ms": str(self.tsleep)}
        if self.nodrift:
            hdr["X-NoDrift"] = "1"
        try:
            status, raw = self.client.call(service, op, data, hdr, self.deadline_s)
        except CallTimeout:
            self.calls[cid]["outcome"] = "timeout"
            raise CallTimeout(service, cid)
        self.bytes += len(raw)
        if status != 200:
            self.calls[cid]["outcome"] = "error"
            raise CallError(service, status, raw, cid)
        self.calls[cid]["outcome"] = "returned"
        return cid, raw

    def detect(self, cid, component, kind):
        self.detections.append({"cid": cid, "component": component, "kind": kind})


def _cv(ctx, *a, **k):
    t = time.perf_counter()
    try:
        return C.validate(*a, **k)
    finally:
        ctx.vtime += time.perf_counter() - t


def _cvs(ctx, *a, **k):
    t = time.perf_counter()
    try:
        return C.validate_slim(*a, **k)
    finally:
        ctx.vtime += time.perf_counter() - t


def _answer(status, a=None, reason=None):
    out = {"status": status, "verdict": None, "category": None, "confidence": 0.0, "usable": False, "reason": reason}
    if a:
        out.update(verdict=a["verdict"], category=a["category"], confidence=a["confidence"], usable=bool(a["usable"]))
    return out


# ============================================================================ boundary guards

def guard_eb(ctx, cid, service, raw):
    """EvidenceBundle boundary (invariant I2). Returns (outcome, bundle_or_None)."""
    try:
        obj = json.loads(raw)
    except ValueError:
        ctx.detect(cid, service, "malformed")
        return "malformed", None
    try:
        _cv(ctx, "EvidenceBundle", obj, producer=service)
    except C.ContractViolation:
        ctx.detect(cid, service, "malformed")
        return "malformed", None
    if obj["status"] == "empty":
        ctx.detect(cid, service, "empty")
        return "empty", obj
    return "ok", obj


# ============================================================================ DelegationGraph

def build_graph(frame_ref, use_eb=True, raw=False, fallback=True, max_attempts=None, slot=None):
    slot = slot or {}
    if raw:
        ops = {"retrieve": "retrieve_raw", "correlate": "correlate_raw", "synthesize": "synthesize_raw"}
    elif use_eb:
        ops = {"retrieve": "retrieve", "correlate": "correlate", "synthesize": "synthesize"}
    else:
        ops = {"retrieve": None, "correlate": "correlate_native", "synthesize": "synthesize_native"}

    def rop(service):
        return ops["retrieve"] or V.OP_NAME[_variant_of(service)]

    siem, edr = slot.get("siem", "siem"), slot.get("edr", "edr")
    nodes = [
        {"id": "n_siem", "task": "retrieve", "capability": "retrieve_siem", "assigned_to": siem, "op": rop(siem)},
        {"id": "n_edr", "task": "retrieve", "capability": "retrieve_edr", "assigned_to": edr, "op": rop(edr)},
        {"id": "n_corr", "task": "correlate", "capability": "correlate", "assigned_to": "correlator", "op": ops["correlate"]},
        {"id": "n_synth", "task": "synthesize", "capability": "synthesize", "assigned_to": "synthesis", "op": ops["synthesize"]},
    ]
    deps = [{"from": "n_siem", "to": "n_corr"}, {"from": "n_edr", "to": "n_corr"}, {"from": "n_corr", "to": "n_synth"}]
    pol = dict(POLICY)
    if max_attempts is not None:
        pol["max_attempts"] = max_attempts
    retry = {n: dict(pol) for n in ("n_siem", "n_edr", "n_corr")}
    fb = {}
    if fallback:
        fb = {"n_siem": {"alternates": [{"assigned_to": "siem_replica", "op": rop("siem_replica")}], "on": list(POLICY["retry_on"])},
              "n_edr": {"alternates": [{"assigned_to": "edr_replica", "op": rop("edr_replica")}], "on": list(POLICY["retry_on"])},
              "n_corr": {"alternates": [{"assigned_to": "correlator_lite", "op": ops["correlate"]}], "on": list(POLICY["retry_on"])}}
    return {"contract": "DelegationGraph", "contract_version": "1.0", "graph_id": "dg-%s" % frame_ref[-12:].rjust(8, "0"),
            "frame_ref": frame_ref, "nodes": nodes, "dependencies": deps, "retry_policy": retry, "fallback_policy": fb}


def _variant_of(service):
    if service.startswith("siem_") and service[5:] in V.VARIANTS:
        return service[5:]
    return {"siem": "as_is", "edr": "as_is", "siem_replica": "docs_relevance", "edr_replica": "nested_ret"}[service]


def _topo(g):
    indeg = {n["id"]: 0 for n in g["nodes"]}
    for d in g["dependencies"]:
        indeg[d["to"]] += 1
    order, ready = [], [n["id"] for n in g["nodes"] if indeg[n["id"]] == 0]
    while ready:
        n = ready.pop(0)
        order.append(n)
        for d in g["dependencies"]:
            if d["from"] == n:
                indeg[d["to"]] -= 1
                if indeg[d["to"]] == 0:
                    ready.append(d["to"])
    return order


# backend-specific extraction used by the No-EvidenceBundle design (consumer-side code)
NATIVE_EXTRACT = {
    "siem": lambda n: n["hits"],                                                    # TOUCHPOINT coordinator.extract[siem]
    "edr": lambda n: n["hits"],
    "siem_replica": lambda n: [{"rec": d["doc"], "score": d["relevance"]} for d in n["docs"]],
    "edr_replica": lambda n: n["data"]["result"]["hits"],
}


def _extractor(service):
    # a swapped-in backend occupies the 'siem' slot: the consumer still uses the siem extractor
    return NATIVE_EXTRACT.get(service, NATIVE_EXTRACT["siem"])


class GraphExecutor:
    """Generic DelegationGraph interpreter. Coordination policy is data, not code."""

    def __init__(self, ctx, g, mode, frame=None, request=None, request_id=None):
        self.ctx, self.g, self.mode = ctx, g, mode   # mode: eb | raw | native
        self.frame, self.request, self.request_id = frame, request, request_id
        self.state = {}

    def _body(self, node, results):
        t = node["task"]
        if self.mode == "native":
            q = self.native_q
            if t == "retrieve":
                return {"host": q["host"], "start": q["start"], "end": q["end"]}
            if t == "correlate":
                hits = {}
                for nid, src in (("n_siem", "siem"), ("n_edr", "edr")):
                    r = results.get(nid)
                    if r and r[0] == "ok":
                        hits[src] = r[1]
                return {"host": q["host"], "hits": hits}
            c = results["n_corr"][1]
            return {"target": q["target"], "scores": c["scores"], "sources_present": c["sources_present"]}
        base = {"frame": self.frame} if self.mode == "eb" else {"request": self.request, "request_id": self.request_id}
        if t == "retrieve":
            return base
        if t == "correlate":
            b = dict(base)
            b["bundles"] = [results[n][1] for n in ("n_siem", "n_edr") if results.get(n) and results[n][0] == "ok"]
            return b
        b = dict(base)
        b["correlation"] = results["n_corr"][1]
        return b

    def _invoke(self, node, target, results):
        svc, op = target["assigned_to"], target["op"]
        try:
            cid, raw = self.ctx.call(svc, op, self._body(node, results))
        except CallTimeout as e:
            self.ctx.detect(e.cid, svc, "timeout")
            return "timeout", None
        except CallError as e:
            self.ctx.detect(e.cid, svc, "error")
            return "error", None
        if node["task"] == "synthesize":
            return "ok", json.loads(raw)
        if self.mode == "native":
            try:
                obj = json.loads(raw)
                if node["task"] == "retrieve":
                    obj = _extractor(svc)(obj)
                    if not isinstance(obj, list):
                        raise TypeError("not a list")
                    if len(obj) == 0:
                        self.ctx.detect(cid, svc, "empty")
                        return "empty", obj
                else:
                    obj["scores"], obj["sources_present"]
                    if not obj["scores"] and not obj["sources_present"]:
                        self.ctx.detect(cid, svc, "empty")
                        return "empty", obj
            except (ValueError, KeyError, TypeError, IndexError, AttributeError):
                self.ctx.detect(cid, svc, "malformed")
                return "malformed", None
            return "ok", obj
        return guard_eb(self.ctx, cid, svc, raw)

    def run(self):
        nodes = {n["id"]: n for n in self.g["nodes"]}
        results = {}
        for nid in _topo(self.g):
            node = nodes[nid]
            if node["task"] == "synthesize" and (results.get("n_corr") is None or results["n_corr"][0] != "ok"):
                self.state[nid] = {"status": "skipped"}
                raise Failed("coordinator", "no correlation available")
            pol = self.g["retry_policy"].get(nid, {"max_attempts": 1, "backoff_ms": 0, "retry_on": []})
            fb = self.g["fallback_policy"].get(nid, {"alternates": [], "on": []})
            targets = [{"assigned_to": node["assigned_to"], "op": node["op"]}] + fb["alternates"]
            st = {"attempts": [], "served_by": None, "status": None}
            final, last = None, ("error", None)
            for ti, tgt in enumerate(targets):
                if ti > 0 and last[0] not in fb["on"]:
                    break
                for a in range(pol["max_attempts"]):
                    out = self._invoke(node, tgt, results)
                    st["attempts"].append([tgt["assigned_to"], out[0]])
                    if out[0] == "ok":
                        final = out
                        st["served_by"] = tgt["assigned_to"]
                        break
                    last = out
                    if out[0] not in pol["retry_on"]:
                        break
                    if a + 1 < pol["max_attempts"] and pol["backoff_ms"]:
                        time.sleep(pol["backoff_ms"] / 1000.0)
                if final:
                    break
            results[nid] = final or last
            st["status"] = results[nid][0]
            self.state[nid] = st
        self.ctx.trace = self.state
        return results["n_synth"][1]


# ============================================================================ conditions

def run_full(ctx, fallback=True, max_attempts=None, emit_version=None):
    case = ctx.case
    rid = "%d-%d" % (case["seed"], case["case_id"])
    # --- Semantic Intent Layer (I1: ingress gate; only a valid IntentFrame proceeds)
    try:
        cid, raw = ctx.call("intent", "normalize", {"request": case["request"], "request_id": rid})
    except (CallTimeout, CallError) as e:
        raise Failed("intent", type(e).__name__)
    frame = json.loads(raw)
    if "error" in frame:
        return _answer("rejected", reason=frame["error"])
    try:
        _cv(ctx, "IntentFrame", frame, producer="intent")
    except C.ContractViolation as e:
        return _answer("rejected", reason=str(e))
    # --- Autonomous Coordination Layer (I3: plan validated before execution)
    g = build_graph(frame["frame_id"], use_eb=True, fallback=fallback, max_attempts=max_attempts, slot=ctx.slot)
    _cv(ctx, "DelegationGraph", g, producer="coordinator", registry=REGISTRY)
    a = GraphExecutor(ctx, g, "eb", frame=frame).run()
    return _answer("answered", a)


def run_no_if(ctx):
    case = ctx.case
    rid = "%d-%d" % (case["seed"], case["case_id"])
    g = build_graph("req-" + rid, use_eb=True, raw=True, slot=ctx.slot)
    _cv(ctx, "DelegationGraph", g, producer="coordinator", registry=REGISTRY)
    a = GraphExecutor(ctx, g, "raw", request=case["request"], request_id=rid).run()
    return _answer("answered", a)


def run_no_eb(ctx):
    case = ctx.case
    rid = "%d-%d" % (case["seed"], case["case_id"])
    try:
        cid, raw = ctx.call("intent", "normalize", {"request": case["request"], "request_id": rid})
    except (CallTimeout, CallError) as e:
        raise Failed("intent", type(e).__name__)
    frame = json.loads(raw)
    if "error" in frame:
        return _answer("rejected", reason=frame["error"])
    _cv(ctx, "IntentFrame", frame, producer="intent")
    g = build_graph(frame["frame_id"], use_eb=False, slot=ctx.slot)
    _cv(ctx, "DelegationGraph", g, producer="coordinator", registry=REGISTRY)
    ex = GraphExecutor(ctx, g, "native", frame=frame)
    tw = frame["constraints"]["time_window"]
    ex.native_q = {"host": frame["entities"][0]["value"], "start": tw["start"], "end": tw["end"],
                   "target": frame["target_confidence"]}
    return _answer("answered", ex.run())


def run_no_dg(ctx):
    """IntentFrame + EvidenceBundle retained; coordination hand-coded with the same policy."""
    case = ctx.case
    rid = "%d-%d" % (case["seed"], case["case_id"])
    try:
        cid, raw = ctx.call("intent", "normalize", {"request": case["request"], "request_id": rid})
    except (CallTimeout, CallError) as e:
        raise Failed("intent", type(e).__name__)
    frame = json.loads(raw)
    if "error" in frame:
        return _answer("rejected", reason=frame["error"])
    _cv(ctx, "IntentFrame", frame, producer="intent")

    def fetch(primary, alternate, op, body):
        # hard-coded: 2 attempts per target, then the alternate -- same as POLICY/FALLBACK
        last = ("error", None)
        for svc in (primary, alternate):
            for attempt in range(2):
                try:
                    cid, raw = ctx.call(svc, op, body)
                except CallTimeout as e:
                    ctx.detect(e.cid, svc, "timeout")
                    last = ("timeout", None)
                except CallError as e:
                    ctx.detect(e.cid, svc, "error")
                    last = ("error", None)
                else:
                    out = guard_eb(ctx, cid, svc, raw)
                    if out[0] == "ok":
                        return out
                    last = out
                if attempt == 0:
                    time.sleep(0.002)
        return last

    siem = fetch(ctx.svc("siem"), "siem_replica", "retrieve", {"frame": frame})
    edr = fetch("edr", "edr_replica", "retrieve", {"frame": frame})
    bundles = [b for o, b in (siem, edr) if o == "ok"]
    corr = fetch("correlator", "correlator_lite", "correlate", {"frame": frame, "bundles": bundles})
    if corr[0] != "ok":
        raise Failed("controller", "no correlation available")
    cid, raw = ctx.call("synthesis", "synthesize", {"frame": frame, "correlation": corr[1]})
    return _answer("answered", json.loads(raw))


def run_slim(ctx):
    case = ctx.case
    cid, raw = ctx.call("intent", "normalize_slim", {"request": case["request"]})
    intent = json.loads(raw)
    if "error" in intent:
        return _answer("rejected", reason=intent["error"])
    _cvs(ctx, "intent", intent, producer="intent")
    ev = []
    for svc in ("siem", "edr"):
        cid, raw = ctx.call(svc, "retrieve_slim", {"intent": intent})
        ev.append(_cvs(ctx, "evidence", json.loads(raw), producer=svc))
    cid, raw = ctx.call("correlator", "correlate_slim", {"intent": intent, "evidence": ev})
    corr = _cvs(ctx, "correlation", json.loads(raw), producer="correlator")
    cid, raw = ctx.call("synthesis", "synthesize_slim", {"intent": intent, "correlation": corr})
    return _answer("answered", json.loads(raw))


def run_adhoc(ctx, inline=False):
    """Ad hoc controller. Without `inline`, any exception aborts the request."""
    case = ctx.case
    p = parse_v2(case["request"])          # shared normalizer library
    if p is None:
        return _answer("rejected", reason="no host")
    q = {"host": p["host"], "start": p["start"], "end": p["end"]}

    def siem_extract(n):
        return n["hits"]                    # TOUCHPOINT controller.siem_extract

    def call_extract(svc, op, body, extract):
        cid, raw = ctx.call(svc, op, body)
        return cid, extract(json.loads(raw))

    def recover(primary, op, extract, alt):
        """Inline recovery: same parameters as POLICY/FALLBACK, hard-coded for these backends."""
        last = None
        for svc, o, ex in ((primary, op, extract), alt):
            for attempt in range(2):
                try:
                    cid, hits = call_extract(svc, o, q, ex)
                except CallTimeout as e:
                    ctx.detect(e.cid, svc, "timeout"); last = "timeout"
                except CallError as e:
                    ctx.detect(e.cid, svc, "error"); last = "error"
                except (ValueError, KeyError, TypeError, IndexError, AttributeError):
                    ctx.detect(ctx.calls[-1]["cid"], svc, "malformed"); last = "malformed"
                else:
                    if hits:
                        return hits
                    ctx.detect(cid, svc, "empty"); last = "empty"
                if attempt == 0:
                    time.sleep(0.002)
        return None

    siem_svc = ctx.svc("siem")
    if inline:
        siem = recover(siem_svc, "search_hits", siem_extract,           # TOUCHPOINT controller.siem_call
                       ("siem_replica", "find_docs", lambda n: [{"rec": d["doc"], "score": d["relevance"]} for d in n["docs"]]))
        edr = recover("edr", "search_hits", lambda n: n["hits"],
                      ("edr_replica", "search_hits", lambda n: n["data"]["result"]["hits"]))
    else:
        _, siem = call_extract(siem_svc, "search_hits", q, siem_extract)
        _, edr = call_extract("edr", "search_hits", q, lambda n: n["hits"])
    hits = {}
    if siem:
        hits["siem"] = siem
    if edr:
        hits["edr"] = edr
    body = {"host": p["host"], "hits": hits}
    corr = None
    if inline:
        for i, svc in enumerate(("correlator", "correlator", "correlator_lite", "correlator_lite")):
            if i % 2 == 1:
                time.sleep(0.002)
            try:
                cid, raw = ctx.call(svc, "correlate_native", body)
                c = json.loads(raw)
                c["scores"], c["sources_present"]
                if not c["scores"] and not c["sources_present"]:
                    ctx.detect(cid, svc, "empty")
                    continue
                corr = c
                break
            except CallTimeout as e:
                ctx.detect(e.cid, svc, "timeout")
            except CallError as e:
                ctx.detect(e.cid, svc, "error")
            except (ValueError, KeyError, TypeError):
                ctx.detect(ctx.calls[-1]["cid"], svc, "malformed")
        if corr is None:
            raise Failed("controller", "no correlation available")
    else:
        cid, raw = ctx.call("correlator", "correlate_native", body)
        corr = json.loads(raw)
    cid, raw = ctx.call("synthesis", "synthesize_native",
                        {"target": p["target"], "scores": corr["scores"], "sources_present": corr["sources_present"]})
    return _answer("answered", json.loads(raw))


REGISTRY = None


def _registry():
    global REGISTRY
    if REGISTRY is None:
        from .services import registry
        REGISTRY = registry()
    return REGISTRY


CONDITIONS = {
    "full": lambda ctx: run_full(ctx),
    "full_nofallback": lambda ctx: run_full(ctx, fallback=False, max_attempts=1),
    "slim": run_slim,
    "adhoc": lambda ctx: run_adhoc(ctx, inline=False),
    "adhoc_inline": lambda ctx: run_adhoc(ctx, inline=True),
    "no_if": run_no_if,
    "no_if_nodrift": run_no_if,
    "no_eb": run_no_eb,
    "no_dg": run_no_dg,
}


def run_case(condition, client, case, scale, fault_rate=0.0, deadline_ms=5000, timeout_sleep_ms=0, slot=None):
    """Execute one case under one condition; returns a flat result row."""
    _registry()
    ctx = Ctx(client, case, scale, fault_rate, deadline_ms, timeout_sleep_ms, nodrift=(condition == "no_if_nodrift"))
    if slot:
        ctx.slot = dict(slot)
    t0 = time.perf_counter()
    err = None
    try:
        ans = CONDITIONS[condition](ctx)
    except Failed as e:
        ans, err = _answer("failed", reason=e.reason), e.component
    except (CallTimeout, CallError) as e:
        # transport-level error records name the service that was called
        ans, err = _answer("failed", reason=type(e).__name__), e.service
        ctx.detect(e.cid, e.service, "timeout" if isinstance(e, CallTimeout) else "error")
    except C.ContractViolation as e:
        ans, err = _answer("failed", reason="contract"), e.producer
    except Exception as e:  # consumer-side exception in controller code
        ans, err = _answer("failed", reason=type(e).__name__), "controller"
    lat = (time.perf_counter() - t0) * 1000.0
    exp = case["expected"]
    if exp["verdict"] == "invalid":
        correct = ans["status"] == "rejected"
    else:
        correct = ans["status"] == "answered" and ans["verdict"] == exp["verdict"] and ans["category"] == exp["category"]
    faults = [c for c in ctx.calls if c["fault"]]
    detected_cids = {(d["cid"], d["component"]) for d in ctx.detections}
    localized = sum(1 for c in faults if (c["cid"], c["service"]) in detected_cids)
    spurious = sum(1 for c in ctx.calls if c["outcome"] == "timeout" and not (c["fault"] and c["fault"][0] == "timeout"))
    fk = defaultdict(int)
    for c in faults:
        fk[c["fault"][0] if c["fault"][0] != "malformed" else "malformed_" + c["fault"][1]] += 1
    loc_k = defaultdict(int)
    for c in faults:
        if (c["cid"], c["service"]) in detected_cids:
            loc_k[c["fault"][0] if c["fault"][0] != "malformed" else "malformed_" + c["fault"][1]] += 1
    return {
        "condition": condition, "seed": case["seed"], "case_id": case["case_id"], "scale": scale,
        "fault_rate": fault_rate, "category": case["category"], "invalid": case["invalid"],
        "target": case["target_confidence"], "latency_ms": round(lat, 4),
        "validation_ms": round(ctx.vtime * 1000.0, 4), "bytes": ctx.bytes,
        "n_calls": len(ctx.calls), "status": ans["status"], "verdict": ans["verdict"], "answer_category": ans["category"],
        "confidence": ans["confidence"], "usable": bool(ans["usable"]), "correct": bool(correct),
        "error_component": err, "faults": len(faults), "faults_localized": localized,
        "faults_by_kind": dict(fk), "localized_by_kind": dict(loc_k), "spurious_timeouts": spurious,
        "executed_invalid": bool(case["invalid"] and ans["status"] != "rejected" and len(ctx.calls) > 1),
        "trace_available": bool(ctx.trace),
        # interface failures (malformed/error) observed on the backend occupying the swapped slot
        "slot_incompat": sum(1 for d in ctx.detections if ctx.slot and d["component"] == ctx.slot.get("siem")
                             and d["kind"] in ("malformed", "error")),
    }
