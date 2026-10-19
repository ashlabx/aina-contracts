"""Unit tests: contract validation, invariants I1-I4, contract evolution, adapters, touchpoints.

Run:  python -m unittest discover -s tests -v
"""
import copy
import json
import os
import re
import unittest

from aina import contracts as C
from aina import services as S
from aina import variants as V
from aina.intent import parse_v2
from aina.orchestrators import TOUCHPOINTS, build_graph, guard_eb, Ctx, run_case
from aina.transport import InProcClient
from aina.workload import make_case, case_records
from aina import reasoning as R

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _frame():
    return S.make_intent_frame("1-1", parse_v2("Investigate host WS-0142 over the last 24 hours."))


def _bundle(variant="as_is", version=None):
    case = make_case(1, 3)
    recs = case_records(case, 640)["siem"]
    hits = R.retrieve(recs, case["host"], 0, 10 ** 9)
    as_is = V.NORMALIZE[variant](V.produce(variant, hits, R.all_matches(recs, case["host"], 0, 10 ** 9)))
    b = S.make_evidence_bundle("siem", "siem", "adapter:" + variant, "if-x", {"host": case["host"]}, as_is)
    return S.evolve_bundle(b, version) if version else b


class TestIntentFrame(unittest.TestCase):
    def test_valid(self):
        C.validate("IntentFrame", _frame())

    def test_I1_unresolvable_request_rejected_before_execution(self):
        svc = S.IntentService()
        out = svc.call("normalize", {"request": "Check for signs of compromise during the last day.", "request_id": "x"}, {})
        self.assertIn("error", out)

    def test_bad_window_semantic(self):
        f = _frame()
        f["constraints"]["time_window"]["start"] = f["constraints"]["time_window"]["end"]
        with self.assertRaises(C.ContractViolation):
            C.validate("IntentFrame", f)

    def test_two_hosts_rejected(self):
        f = _frame()
        f["entities"].append({"type": "host", "value": "WS-0001"})
        with self.assertRaises(C.ContractViolation):
            C.validate("IntentFrame", f)


class TestEvidenceBundle(unittest.TestCase):
    def test_valid_all_variants_identical_after_adapter(self):
        ref = _bundle("as_is")
        C.validate("EvidenceBundle", ref)
        for v in V.VARIANTS:
            b = _bundle(v)
            C.validate("EvidenceBundle", b)
            self.assertEqual([i["item_id"].split(":")[1] for i in b["evidence_items"]],
                             [i["item_id"].split(":")[1] for i in ref["evidence_items"]], v)
            self.assertEqual(b["salience"], ref["salience"], v)

    def test_salience_length_semantic(self):
        b = _bundle()
        b["salience"].append(0.5)
        with self.assertRaises(C.ContractViolation):
            C.validate("EvidenceBundle", b)

    def test_status_consistency(self):
        b = _bundle()
        b["status"] = "empty"
        with self.assertRaises(C.ContractViolation):
            C.validate("EvidenceBundle", b)

    def test_wrong_type_detected(self):
        b = _bundle()
        b["evidence_items"][0]["ts"] = "yesterday"
        with self.assertRaises(C.ContractViolation):
            C.validate("EvidenceBundle", b)


class TestContractEvolution(unittest.TestCase):
    """Reviewer B: how do contracts evolve? Minor = additive & accepted; major = rejected at boundary."""

    def test_minor_version_accepted_by_1_0_consumer(self):
        b = _bundle(version="1.1")
        self.assertEqual(b["contract_version"], "1.1")
        C.validate("EvidenceBundle", b)  # unknown top-level field 'time_scope' is ignored

    def test_major_version_rejected_and_attributed(self):
        b = _bundle(version="2.0")
        with self.assertRaises(C.VersionMismatch) as cm:
            C.validate("EvidenceBundle", b, producer="siem")
        self.assertEqual(cm.exception.producer, "siem")

    def test_unknown_nested_field_rejected(self):
        b = _bundle()
        b["evidence_items"][0]["extra"] = 1
        with self.assertRaises(C.ContractViolation):
            C.validate("EvidenceBundle", b)


class TestDelegationGraph(unittest.TestCase):
    def setUp(self):
        self.reg = S.registry()

    def test_valid(self):
        C.validate("DelegationGraph", build_graph("if-abcdef012345"), registry=self.reg)

    def test_cycle_rejected(self):
        g = build_graph("if-abcdef012345")
        g["dependencies"].append({"from": "n_synth", "to": "n_siem"})
        with self.assertRaises(C.ContractViolation):
            C.validate("DelegationGraph", g, registry=self.reg)

    def test_I3_binding_to_service_without_capability_rejected(self):
        g = build_graph("if-abcdef012345")
        g["nodes"][0]["assigned_to"] = "edr"
        with self.assertRaises(C.ContractViolation):
            C.validate("DelegationGraph", g, registry=self.reg)

    def test_policy_on_unknown_node_rejected(self):
        g = build_graph("if-abcdef012345")
        g["retry_policy"]["n_ghost"] = {"max_attempts": 1, "backoff_ms": 0, "retry_on": []}
        with self.assertRaises(C.ContractViolation):
            C.validate("DelegationGraph", g, registry=self.reg)


class TestI4(unittest.TestCase):
    """I4: a validation failure is handled by the layer that owns the contract; feedback crosses
    layers only as typed signals, and only the intent layer produces a new IntentFrame revision."""

    def test_eb_failure_does_not_touch_intent_frame(self):
        case = make_case(1, 5)
        ctx = Ctx(InProcClient(), case, 640, 0.0, 5000, 0)
        b = _bundle()
        del b["provenance"]
        out = guard_eb(ctx, 0, "siem", json.dumps(b).encode())
        self.assertEqual(out[0], "malformed")
        self.assertEqual(ctx.detections[0]["component"], "siem")

    def test_refine_signal_produces_new_revision_only_in_intent_layer(self):
        f = _frame()
        f2 = S.IntentService().call("refine", {"frame": f, "reason": "empty_all", "suggestion": "widen_time_window"}, {})
        self.assertEqual(f2["revision"], f["revision"] + 1)
        self.assertEqual(f["revision"], 1)  # original unchanged
        C.validate("IntentFrame", f2)
        tw, tw2 = f["constraints"]["time_window"], f2["constraints"]["time_window"]
        self.assertEqual(tw2["end"] - tw2["start"], 2 * (tw["end"] - tw["start"]))

    def test_validators_are_layer_scoped(self):
        self.assertEqual(set(C.OWNER_LAYER), {"IntentFrame", "EvidenceBundle", "DelegationGraph"})
        self.assertEqual(len(set(C.OWNER_LAYER.values())), 3)


class TestTouchpoints(unittest.TestCase):
    def test_declared_touchpoints_exist_in_source(self):
        src = ""
        for f in ("orchestrators.py", "services.py"):
            with open(os.path.join(ROOT, "aina", f)) as fh:
                src += fh.read()
        for design, tps in TOUCHPOINTS.items():
            for loc, _ in tps:
                self.assertIn("TOUCHPOINT " + loc, src, loc)


class TestFaultIsolation(unittest.TestCase):
    def test_structural_corruption_does_not_leak_into_cached_data(self):
        cl = InProcClient()
        cases = [make_case(1, i) for i in range(40)]
        clean = [run_case("full", cl, c, 640) for c in cases]
        for c, r in zip(cases, clean):
            run_case("adhoc_inline", cl, c, 640, fault_rate=0.4, deadline_ms=60, timeout_sleep_ms=0)  # native payloads reference records
            again = run_case("full", cl, c, 640)
            self.assertEqual(again["n_calls"], r["n_calls"], c["case_id"])  # no retries => no poisoned data
        for c, r in zip(cases, clean):
            self.assertEqual(run_case("full", cl, c, 640)["answer_category"], r["answer_category"])


class TestEndToEnd(unittest.TestCase):
    def test_conditions_agree_without_faults(self):
        cl = InProcClient()
        for i in range(30):
            c = make_case(7, i)
            ref = run_case("full", cl, c, 320)
            for cond in ("slim", "adhoc", "adhoc_inline", "no_eb", "no_dg"):
                r = run_case(cond, cl, c, 320)
                self.assertEqual((r["status"], r["verdict"], r["answer_category"]),
                                 (ref["status"], ref["verdict"], ref["answer_category"]), (cond, i))


if __name__ == "__main__":
    unittest.main()
