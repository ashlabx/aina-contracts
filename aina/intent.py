"""Request interpretation.

parse_v2  -- the canonical normalizer (used by the intent service, and by the ad hoc
             controller as a shared library, so both see identical interpretation).
parse_v1  -- an older parser, used only to model *interpretation drift* in the
             No-IntentFrame ablation, where each downstream service interprets the raw
             request independently and services are maintained on different release
             trains. v1 is case-sensitive on host names, has no IP or FQDN handling, and
             recognises only "last N hours|days"; otherwise it defaults to a 6 h window.
"""
import re

from .workload import T0, resolve_ip

_HOST_RE = re.compile(r"\b([A-Za-z]{2,4}-\d{3,4})(?:\.[A-Za-z0-9-]+)*\b")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_WIN_RE = re.compile(r"\b(?:last|past)\s+(\d+)\s*(h|hours?|d|days?)\b", re.I)


def parse_v2(text):
    """Return dict(host, start, end, target) or None if the request cannot be resolved."""
    host = None
    m = _HOST_RE.search(text)
    if m:
        host = m.group(1).upper()
    else:
        m = _IP_RE.search(text)
        if m:
            host = resolve_ip(m.group(1))
    if host is None:
        return None
    t = text.lower()
    mins = None
    m = _WIN_RE.search(t)
    if m:
        n = int(m.group(1))
        mins = n * 60 if m.group(2).startswith("h") else n * 1440
    elif "last day" in t or "past day" in t or "since yesterday" in t:
        mins = 1440
    if mins is None:
        mins = 1440
    target = 0.8 if "high confidence" in t else 0.6
    return {"host": host, "start": T0 - mins, "end": T0, "target": target}


_V1_HOST = re.compile(r"\b([A-Z]{2,4}-\d{3,4})\b")
_V1_WIN = re.compile(r"\blast (\d+) (hours|days)\b")


def parse_v1(text):
    m = _V1_HOST.search(text)
    host = m.group(1) if m else None
    m = _V1_WIN.search(text)
    if m:
        n = int(m.group(1))
        mins = n * 60 if m.group(2) == "hours" else n * 1440
    else:
        mins = 360
    target = 0.8 if "High confidence" in text else 0.6
    return {"host": host, "start": T0 - mins, "end": T0, "target": target}


PARSERS = {"v1": parse_v1, "v2": parse_v2}
