"""Eleven heterogeneous retrieval-backend variants (Experiment B) and their producer-side adapters.

Every variant wraps the *same* retrieval engine; variants differ only in the callable (op)
name and the shape of the returned payload -- the interface heterogeneity Experiment B tests.

For each variant we provide
  * produce_<variant>(hits)     -> native payload (what the backend returns on the wire)
  * normalize_<variant>(native) -> canonical "as_is" payload  {"hits": [{"rec":..., "score":...}]}
The normalizer is the producer-side adapter: in the layered design it runs inside the backend
service, before the EvidenceBundle boundary, so consumers never see the native shape.

ASPECTS lists which interface aspects differ from the reference (as_is) backend; it is used to
compute consumer-side integration effort (number of consumer code locations that depend on an
aspect that changed). See orchestrators.TOUCHPOINTS.
"""
from .reasoning import TOP_K, rank

VARIANTS = ["as_is", "shape_mismatch", "field_mismatch", "tuple", "all_matches", "dict_results",
            "docs_relevance", "snippet", "records_conf", "tuple_ret", "nested_ret"]

OP_NAME = {v: "search_hits" for v in VARIANTS}
OP_NAME.update({"all_matches": "all_matches", "docs_relevance": "find_docs", "records_conf": "query_records"})

ASPECTS = {
    "as_is": set(),
    "shape_mismatch": {"container"},
    "field_mismatch": {"field_rec", "field_score"},
    "tuple": {"item_shape"},
    "all_matches": {"op_name", "container", "ordering"},
    "dict_results": {"container"},
    "docs_relevance": {"op_name", "container", "field_rec", "field_score"},
    "snippet": {"field_rec", "record_encoding"},
    "records_conf": {"op_name", "container", "item_shape"},
    "tuple_ret": {"container"},
    "nested_ret": {"container"},
}

INT_FIELDS = {"ts", "logon_type", "dst_port", "bytes_out", "bytes_in"}
_SEP = " | "


def _as_is_items(hits):
    return [{"rec": r, "score": s} for r, s in hits]


# ---------------------------------------------------------------- producers (native payloads)

def produce(variant, hits, all_hits=None):
    if variant == "as_is":
        return {"hits": _as_is_items(hits)}
    if variant == "shape_mismatch":
        return _as_is_items(hits)
    if variant == "field_mismatch":
        return {"hits": [{"record": r, "relevance": s} for r, s in hits]}
    if variant == "tuple":
        return {"hits": [[r, s] for r, s in hits]}
    if variant == "all_matches":
        return {"matches": _as_is_items(all_hits)}
    if variant == "dict_results":
        return {"results": {r["rid"]: {"rec": r, "score": s} for r, s in hits}}
    if variant == "docs_relevance":
        return {"docs": [{"doc": r, "relevance": s} for r, s in hits]}
    if variant == "snippet":
        return {"hits": [{"id": r["rid"], "score": s,
                          "snippet": _SEP.join("%s=%s" % (k, v) for k, v in r.items())} for r, s in hits]}
    if variant == "records_conf":
        return {"records": [r for r, _ in hits], "confidences": [s for _, s in hits]}
    if variant == "tuple_ret":
        return [_as_is_items(hits), len(hits)]
    if variant == "nested_ret":
        return {"data": {"result": {"hits": _as_is_items(hits)}}}
    raise ValueError(variant)


def empty_native(variant):
    return produce(variant, [], all_hits=[])


# ---------------------------------------------------------------- adapters (native -> as_is)

def normalize_as_is(n):
    return {"hits": n["hits"]}


def normalize_shape_mismatch(n):
    return {"hits": n}


def normalize_field_mismatch(n):
    return {"hits": [{"rec": h["record"], "score": h["relevance"]} for h in n["hits"]]}


def normalize_tuple(n):
    return {"hits": [{"rec": r, "score": s} for r, s in n["hits"]]}


def normalize_all_matches(n):
    ranked = rank([(h["rec"], h["score"]) for h in n["matches"]], TOP_K)
    return {"hits": [{"rec": r, "score": s} for r, s in ranked]}


def normalize_dict_results(n):
    return {"hits": sorted(n["results"].values(), key=lambda h: (-h["score"], -h["rec"]["ts"]))}


def normalize_docs_relevance(n):
    return {"hits": [{"rec": d["doc"], "score": d["relevance"]} for d in n["docs"]]}


def normalize_snippet(n):
    out = []
    for h in n["hits"]:
        rec = {}
        for part in h["snippet"].split(_SEP):
            k, v = part.split("=", 1)
            rec[k] = int(v) if k in INT_FIELDS else v
        out.append({"rec": rec, "score": h["score"]})
    return {"hits": out}


def normalize_records_conf(n):
    return {"hits": [{"rec": r, "score": s} for r, s in zip(n["records"], n["confidences"])]}


def normalize_tuple_ret(n):
    return {"hits": n[0]}


def normalize_nested_ret(n):
    return {"hits": n["data"]["result"]["hits"]}


NORMALIZE = {v: globals()["normalize_" + v] for v in VARIANTS}


def adapter_loc(variant):
    """Non-blank source lines of the producer-side adapter for a variant."""
    import inspect
    src = inspect.getsource(NORMALIZE[variant])
    return sum(1 for line in src.splitlines() if line.strip())
