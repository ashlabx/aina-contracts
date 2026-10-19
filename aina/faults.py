"""Deterministic fault injection.

Whether call attempt `a` of service `s` for case `c` under seed `k` is faulty depends only on
(k, c, s, a, rate), so every architectural condition faces the *same* fault schedule (paired
design) and the driver can compute ground truth without trusting the services.

Fault kinds (equal thirds of the fault rate):
  timeout    -- the service sleeps past the caller's deadline before answering
  malformed  -- half 'truncated' (invalid JSON on the wire), half 'structural' (valid JSON with
                one randomly chosen field deleted or replaced by a value of the wrong type)
  empty      -- a well-formed response containing no results
"""
import hashlib
import json
import random

FAULTABLE = {"siem", "edr", "siem_replica", "edr_replica", "correlator", "correlator_lite"}
KINDS = ["timeout", "malformed", "empty"]


def _u(key, lo):
    h = hashlib.sha256(key.encode()).digest()
    return int.from_bytes(h[lo:lo + 8], "big") / 2.0 ** 64


def fault_for(seed, case_id, service, attempt, rate):
    """Return None or (kind, subkind)."""
    if rate <= 0 or service not in FAULTABLE:
        return None
    key = "%s|%s|%s|%s" % (seed, case_id, service, attempt)
    if _u(key, 0) >= rate:
        return None
    kind = KINDS[min(2, int(_u(key, 8) * 3))]
    sub = None
    if kind == "malformed":
        sub = "truncated" if _u(key, 16) < 0.5 else "structural"
    return kind, sub


def _paths(obj, depth=0, path=()):
    """All (container, key) locations up to depth 4."""
    out = []
    if depth > 4:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append((obj, k, path + (k,)))
            out.extend(_paths(v, depth + 1, path + (k,)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:5]):
            out.append((obj, i, path + (i,)))
            out.extend(_paths(v, depth + 1, path + (i,)))
    return out


def _wrong_type(v):
    if isinstance(v, bool):
        return "yes"
    if isinstance(v, (int, float)):
        return str(v) + "ms"
    if isinstance(v, str):
        return None
    if isinstance(v, list):
        return {"error": "unavailable"}
    if isinstance(v, dict):
        return []
    return 0


def corrupt_structural(obj, key):
    """Delete one field or replace its value with a wrong-typed value (in place). Returns description."""
    rng = random.Random(key)
    locs = _paths(obj)
    if not locs:
        return "no-op"
    cont, k, path = rng.choice(locs)
    if isinstance(cont, dict) and rng.random() < 0.5:
        del cont[k]
        return "delete " + ".".join(map(str, path))
    cont[k] = _wrong_type(cont[k])
    return "retype " + ".".join(map(str, path))


def truncate(raw):
    return raw[: max(1, len(raw) // 2)]
