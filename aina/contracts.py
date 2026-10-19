"""Canonical contracts: machine-readable schemas, validation predicates, and invariant checks.

Each contract has
  * a JSON Schema (aina/schemas/*.schema.json) -- the structural definition, and
  * a semantic predicate (functions below) -- cross-field rules a schema cannot express.

A contract instance is valid iff  major(contract_version) is supported  AND  the instance
satisfies the schema  AND  the semantic predicate returns no errors.

Versioning rule (Section "Contract evolution" of the paper):
  * minor version bump (1.0 -> 1.1): only additive, optional top-level fields. Consumers of any
    1.x accept it (tolerant reader: unknown top-level fields are ignored, the schemas set
    additionalProperties=true at top level only).
  * major version bump (1.x -> 2.0): any removal, rename, or change of meaning. A 1.x consumer
    rejects it at the boundary with VersionMismatch, attributed to the producer.

The validator below implements the subset of JSON Schema (draft 2020-12) used by the schemas,
so the harness runs on the Python standard library alone.
"""
import json
import os
import re

SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "schemas")
_SCHEMA_FILES = {
    "IntentFrame": "intent_frame.schema.json",
    "EvidenceBundle": "evidence_bundle.schema.json",
    "DelegationGraph": "delegation_graph.schema.json",
}
SUPPORTED_MAJOR = {"IntentFrame": 1, "EvidenceBundle": 1, "DelegationGraph": 1}
CURRENT_VERSION = {"IntentFrame": "1.0", "EvidenceBundle": "1.0", "DelegationGraph": "1.0"}

# Layer ownership (used for invariant I4: each layer validates only its own contract)
OWNER_LAYER = {
    "IntentFrame": "semantic_intent",
    "EvidenceBundle": "cognitive_processing",
    "DelegationGraph": "autonomous_coordination",
}

_SCHEMAS = {}


def schema(name):
    if name not in _SCHEMAS:
        with open(os.path.join(SCHEMA_DIR, _SCHEMA_FILES[name])) as f:
            _SCHEMAS[name] = json.load(f)
    return _SCHEMAS[name]


class ContractViolation(Exception):
    """Raised when an instance fails validation. `producer` names the component blamed."""

    def __init__(self, contract, errors, producer=None):
        self.contract = contract
        self.errors = list(errors)
        self.producer = producer
        super().__init__("%s invalid (producer=%s): %s" % (contract, producer, "; ".join(self.errors[:3])))


class VersionMismatch(ContractViolation):
    pass


# --------------------------------------------------------------------------------------------
# Minimal JSON-Schema validator (keywords used by our schemas)
# --------------------------------------------------------------------------------------------

def _is_type(v, t):
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if t == "string":
        return isinstance(v, str)
    if t == "object":
        return isinstance(v, dict)
    if t == "array":
        return isinstance(v, list)
    if t == "boolean":
        return isinstance(v, bool)
    if t == "null":
        return v is None
    raise ValueError("unsupported type %r" % t)


def _validate(inst, sch, root, path, errors, max_errors=20):
    if len(errors) >= max_errors:
        return
    if "$ref" in sch:
        ref = sch["$ref"]
        assert ref.startswith("#/$defs/"), ref
        sch = root["$defs"][ref[len("#/$defs/"):]]
    if "type" in sch:
        types = sch["type"] if isinstance(sch["type"], list) else [sch["type"]]
        if not any(_is_type(inst, t) for t in types):
            errors.append("%s: expected %s, got %s" % (path, "/".join(types), type(inst).__name__))
            return
    if "const" in sch and inst != sch["const"]:
        errors.append("%s: expected const %r" % (path, sch["const"]))
    if "enum" in sch and inst not in sch["enum"]:
        errors.append("%s: %r not in enum" % (path, inst))
    if isinstance(inst, str):
        if "minLength" in sch and len(inst) < sch["minLength"]:
            errors.append("%s: shorter than %d" % (path, sch["minLength"]))
        if "pattern" in sch and not re.search(sch["pattern"], inst):
            errors.append("%s: does not match %s" % (path, sch["pattern"]))
    if _is_type(inst, "number"):
        if "minimum" in sch and inst < sch["minimum"]:
            errors.append("%s: below minimum %s" % (path, sch["minimum"]))
        if "maximum" in sch and inst > sch["maximum"]:
            errors.append("%s: above maximum %s" % (path, sch["maximum"]))
    if isinstance(inst, dict):
        for k in sch.get("required", []):
            if k not in inst:
                errors.append("%s: missing required field '%s'" % (path, k))
        props = sch.get("properties", {})
        for k, v in inst.items():
            if k in props:
                _validate(v, props[k], root, path + "." + k, errors)
            else:
                ap = sch.get("additionalProperties", True)
                if ap is False:
                    errors.append("%s: unexpected field '%s'" % (path, k))
                elif isinstance(ap, dict):
                    _validate(v, ap, root, path + "." + k, errors)
    if isinstance(inst, list):
        if "minItems" in sch and len(inst) < sch["minItems"]:
            errors.append("%s: fewer than %d items" % (path, sch["minItems"]))
        if "items" in sch:
            for i, v in enumerate(inst):
                _validate(v, sch["items"], root, "%s[%d]" % (path, i), errors)


def schema_errors(name, inst):
    errors = []
    s = schema(name)
    _validate(inst, s, s, "$", errors)
    return errors


# --------------------------------------------------------------------------------------------
# Semantic predicates (rules beyond the schema)
# --------------------------------------------------------------------------------------------

def semantic_intent_frame(f):
    e = []
    tw = f["constraints"]["time_window"]
    if not tw["start"] < tw["end"]:
        e.append("time_window.start must be < end")
    hosts = [x for x in f["entities"] if x["type"] == "host"]
    if f["goal"] == "host_investigation" and len(hosts) != 1:
        e.append("host_investigation requires exactly one host entity (found %d)" % len(hosts))
    return e


def semantic_evidence_bundle(b):
    e = []
    items = b["evidence_items"]
    if len(b["salience"]) != len(items):
        e.append("salience length %d != evidence_items length %d" % (len(b["salience"]), len(items)))
    if (b["status"] == "empty") != (len(items) == 0):
        e.append("status '%s' inconsistent with %d items" % (b["status"], len(items)))
    ids = [i["item_id"] for i in items]
    if len(ids) != len(set(ids)):
        e.append("duplicate item_id")
    if any(i["kind"] == "correlation_summary" for i in items):
        for k in ("category_scores", "sources_present"):
            if k not in b["notes"]:
                e.append("correlation bundle missing notes.%s" % k)
    return e


def _has_cycle(node_ids, deps):
    adj = {n: [] for n in node_ids}
    for d in deps:
        adj[d["from"]].append(d["to"])
    state = {}

    def visit(n):
        state[n] = 1
        for m in adj[n]:
            if state.get(m) == 1 or (m not in state and visit(m)):
                return True
        state[n] = 2
        return False

    return any(n not in state and visit(n) for n in node_ids)


def semantic_delegation_graph(g, registry=None):
    """registry: optional dict service_name -> set(capabilities) used to check bindings."""
    e = []
    ids = [n["id"] for n in g["nodes"]]
    if len(ids) != len(set(ids)):
        e.append("duplicate node id")
    idset = set(ids)
    for d in g["dependencies"]:
        if d["from"] not in idset or d["to"] not in idset:
            e.append("dependency references unknown node %s->%s" % (d["from"], d["to"]))
    if not e and _has_cycle(ids, g["dependencies"]):
        e.append("dependency graph has a cycle")
    for k in list(g["retry_policy"]) + list(g["fallback_policy"]):
        if k not in idset:
            e.append("policy references unknown node %s" % k)
    if registry is not None:
        for n in g["nodes"]:
            caps = registry.get(n["assigned_to"])
            if caps is None or n["capability"] not in caps:
                e.append("node %s: %s does not provide capability %s" % (n["id"], n["assigned_to"], n["capability"]))
        for nid, fb in g["fallback_policy"].items():
            cap = next((n["capability"] for n in g["nodes"] if n["id"] == nid), None)
            for alt in fb["alternates"]:
                caps = registry.get(alt["assigned_to"])
                if caps is None or cap not in caps:
                    e.append("fallback for %s: %s does not provide %s" % (nid, alt["assigned_to"], cap))
    return e


_SEMANTIC = {
    "IntentFrame": semantic_intent_frame,
    "EvidenceBundle": semantic_evidence_bundle,
    "DelegationGraph": semantic_delegation_graph,
}


def check_version(name, inst, producer=None):
    v = inst.get("contract_version") if isinstance(inst, dict) else None
    if not isinstance(v, str) or not re.match(r"^[0-9]+\.[0-9]+$", v):
        raise ContractViolation(name, ["missing or malformed contract_version"], producer)
    if int(v.split(".")[0]) != SUPPORTED_MAJOR[name]:
        raise VersionMismatch(name, ["unsupported major version %s (consumer supports %d.x)" % (v, SUPPORTED_MAJOR[name])], producer)


def validate(name, inst, producer=None, registry=None):
    """Full validation of one contract instance. Returns the instance or raises ContractViolation."""
    if not isinstance(inst, dict):
        raise ContractViolation(name, ["instance is not an object"], producer)
    check_version(name, inst, producer)
    errs = schema_errors(name, inst)
    if not errs:
        errs = _SEMANTIC[name](inst, registry) if name == "DelegationGraph" else _SEMANTIC[name](inst)
    if errs:
        raise ContractViolation(name, errs, producer)
    return inst


# --------------------------------------------------------------------------------------------
# "Slim" baseline: lightweight key-presence checks only (no versions, no types, no semantics)
# --------------------------------------------------------------------------------------------

SLIM_KEYS = {
    "intent": ["host", "start", "end", "target"],
    "evidence": ["source", "items"],
    "correlation": ["scores", "sources_present"],
}


def validate_slim(kind, inst, producer=None):
    if not isinstance(inst, dict):
        raise ContractViolation("slim:" + kind, ["not an object"], producer)
    missing = [k for k in SLIM_KEYS[kind] if k not in inst]
    if missing:
        raise ContractViolation("slim:" + kind, ["missing " + ",".join(missing)], producer)
    return inst
