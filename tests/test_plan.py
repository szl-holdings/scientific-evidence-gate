"""The pre-committed PLAN entry and its invariants (section 17.4, extension #2).

The brief's "entry 0" is the ledger's first entry, which is ``seq`` 1. Every
tamper here is applied to a sealed run and replayed through ``decide``,
first without re-sealing (the chain catches it) and then re-sealed the way a
thorough forger would (only facts outside the chain can catch it).
"""

from __future__ import annotations

import copy
import dataclasses
import shutil
import unittest
from typing import Any

from _helpers import TempDirTestCase
from _project import VALID_MANIFEST, ProjectTestCase

from science_gate import mutations
from science_gate._canonical import sha256_canonical
from science_gate.invariants import PLANNED_CONTROLS, InvariantContext, plan_closure, plan_matches_manifest
from science_gate.ledger import (
    GENESIS_SHA256,
    PLAN_KIND,
    PLAN_RESULT,
    PLAN_SCHEMA,
    Ledger,
    LedgerError,
    index_invocations,
    invocation_id_for,
    is_plan_entry,
    parse_jsonl,
    plan_of,
    reseal,
    verify_chain,
)
from science_gate.models import CheckResult, Reason, Status
from science_gate.verifier import (
    REGISTRY,
    DecisionInputs,
    VerificationRun,
    build_plan,
    checker_sha256,
    decide,
    module_source_sha256,
    params_sha256,
    verify,
)


def replay(run: VerificationRun, entries: Any, seal: tuple[str | None, int | None], checks: Any = None) -> DecisionInputs:
    """The sealed run's decision inputs with ``entries`` and ``seal`` in place of its own."""
    assert run.manifest is not None
    return DecisionInputs(
        accounting=run.result.accounting,
        checks=tuple(run.result.checks if checks is None else checks),
        declared_checks={spec.check_id: spec.required for spec in run.manifest.checks},
        entries=tuple(entries),
        ledger_head_sha256=seal[0],
        ledger_length=seal[1],
        run_id=run.result.run_id,
        evidence_manifest=run.evidence_manifest["entries"],
        rows_examined=run.result.counters["rows_examined"],
        expected_plan=run.plan,
        pins=run.pins,
        controls=run.result.controls,
    )


def renamed(checks: Any, invocation_ids: dict[str, str]) -> tuple[CheckResult, ...]:
    """Results pointed at their re-derived invocation ids, as a forger would leave them."""
    return tuple(dataclasses.replace(item, invocation_id=invocation_ids.get(item.invocation_id, item.invocation_id)) for item in checks)


class PlanEntryTests(unittest.TestCase):
    """#2 (a): the demo ledger opens with a PLAN that commits to every check, input and population."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.demo = verify(VALID_MANIFEST)
        cls.written = parse_jsonl(cls.demo.ledger.to_jsonl())

    def test_entry_one_is_the_plan_and_chains_before_the_first_started_entry(self) -> None:
        plan, first_started = self.written[0], self.written[1]
        self.assertEqual(plan["seq"], 1)
        self.assertEqual((plan["result"], plan["check_kind"], plan["check_version"]), (PLAN_RESULT, PLAN_KIND, PLAN_SCHEMA))
        self.assertIsNone(plan["invocation_id"])
        self.assertIsNone(plan["check_id"])
        self.assertEqual((plan["completed_at"], plan["verdict"], plan["reason"]), (None, None, None))
        self.assertEqual(plan["prev_entry_sha256"], GENESIS_SHA256)
        self.assertEqual(first_started["result"], "STARTED")
        self.assertEqual(first_started["prev_entry_sha256"], plan["entry_sha256"])
        self.assertTrue(is_plan_entry(plan))
        self.assertFalse(any(is_plan_entry(entry) for entry in self.written[1:]))

    def test_the_plan_lists_every_required_check_and_input_digest(self) -> None:
        body = plan_of(self.written)
        assert body is not None and self.demo.manifest is not None
        self.assertEqual(body, self.demo.plan)
        self.assertEqual(body["schema"], PLAN_SCHEMA)
        self.assertEqual(body["run_id"], self.demo.result.run_id)
        self.assertEqual(body["manifest_sha256"], self.demo.manifest.sha256)
        required = sorted(spec.check_id for spec in self.demo.manifest.checks if spec.required)
        self.assertEqual([item["check_id"] for item in body["checks"]], required)
        (planned_input,) = body["inputs"]
        declared = self.demo.manifest.inputs[0]
        self.assertEqual(
            planned_input,
            {
                "input_id": "measurements",
                "required": True,
                "format": "csv",
                "declared_sha256": declared.sha256,
                "row_key": ["sample_id"],
                "expected_rows": 6,
                "denominator_source": "INDEPENDENT",
            },
        )
        self.assertEqual(self.written[0]["input_ids"], ["measurements"])
        self.assertEqual(self.written[0]["input_sha256s"], {"measurements": declared.sha256})
        self.assertEqual(body["controls"], sorted(PLANNED_CONTROLS))

    def test_check_digests_follow_the_17_4_formulas(self) -> None:
        body = self.demo.plan
        assert body is not None and self.demo.manifest is not None
        specs = {spec.check_id: spec for spec in self.demo.manifest.checks}
        for item in body["checks"]:
            with self.subTest(check=item["check_id"]):
                spec = specs[item["check_id"]]
                target = REGISTRY[spec.kind]
                self.assertEqual(item["params_sha256"], sha256_canonical(dict(spec.params)))
                self.assertEqual(item["params_sha256"], params_sha256(spec.params))
                expected = sha256_canonical({"target": target, "module_sha256": module_source_sha256(target.partition(":")[0])})
                self.assertEqual(item["checker_sha256"], expected)
                self.assertEqual(item["checker_sha256"], checker_sha256(target, module_source_sha256("science_gate.verifier")))

    def test_pins_are_sorted_by_role_and_path(self) -> None:
        pins = self.demo.plan["pins"]
        self.assertEqual(pins, sorted(pins, key=lambda pin: (pin["role"], pin["path"])))
        self.assertEqual(
            [(pin["role"], pin["path"]) for pin in pins],
            [
                ("check_module", "science_gate.verifier"),
                ("document", "snapshots/accepted.json"),
                ("input", "data/measurements.csv"),
                ("manifest", "manifest.json"),
            ],
        )

    def test_build_plan_is_a_pure_function_of_its_facts(self) -> None:
        demo = self.demo
        assert demo.manifest is not None and demo.plan is not None
        rebuilt = build_plan(demo.manifest, demo.result.accounting, demo.plan["pins"], demo.result.run_id, REGISTRY)
        self.assertEqual(rebuilt, demo.plan)
        self.assertEqual(demo.result.controls["plan"]["entry_sha256"], self.written[0]["entry_sha256"])
        self.assertEqual(
            (demo.result.controls["plan"]["checks_planned"], demo.result.controls["plan"]["inputs_planned"]), (6, 1)
        )


class PlanTamperTests(ProjectTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.base = self.run_verify()
        self.assertEqual(self.base.status, Status.PASS)

    def test_b_a_removed_plan_fails_as_partial_execution_even_when_resealed(self) -> None:
        resealed = reseal(self.base.ledger.entries[1:], self.base.result.run_id)
        self.assertTrue(
            verify_chain(resealed.entries, resealed.ledger_head_sha256, resealed.ledger_length, run_id=self.base.result.run_id).intact,
            "the forged chain itself verifies",
        )
        checks = renamed(self.base.result.checks, dict(resealed.invocation_ids))
        decision = decide(replay(self.base, resealed.entries, (resealed.ledger_head_sha256, resealed.ledger_length), checks))
        (closure,) = [item for item in decision.invariants if item.name == "plan_closure"]
        self.assertIs(closure.holds, False)
        self.assertIn("entry 1 is not a PLAN", closure.detail)
        self.assertEqual((decision.status, decision.reason), (Status.FAIL, Reason.PARTIAL_EXECUTION))

    def test_b_the_m21_removed_plan_operator_is_detected_by_plan_closure(self) -> None:
        operators = getattr(mutations, "OPERATOR_IDS", ())
        if "M21_removed_plan" not in operators:
            self.skipTest("M21_removed_plan is delivered by the mutations builder (section 17.12)")
        tree = self.tmp / "valid"
        shutil.copytree(VALID_MANIFEST.parent, tree)
        report = mutations.mutate(tree / "manifest.json", operators=["M21_removed_plan"])
        (record,) = [item for item in report.mutations if item.mutation_id == "M21_removed_plan"]
        self.assertIs(record.detected, True)
        self.assertIn("invariant:plan_closure", {item.detector for item in record.detecting_invariants_fired})

    def test_c_a_removed_terminal_entry_names_its_check(self) -> None:
        rows = self.result_of(self.base, "rows")
        entries = [
            entry
            for entry in self.base.ledger.entries
            if not (entry["invocation_id"] == rows.invocation_id and entry["result"] != "STARTED")
        ]
        resealed = reseal(entries, self.base.result.run_id)
        checks = renamed(self.base.result.checks, dict(resealed.invocation_ids))
        decision = decide(replay(self.base, resealed.entries, (resealed.ledger_head_sha256, resealed.ledger_length), checks))
        (closure,) = [item for item in decision.invariants if item.name == "plan_closure"]
        self.assertIs(closure.holds, False)
        self.assertIn("planned 'rows' has 1 invocation(s) and 0 terminal result(s)", closure.detail)
        self.assertEqual((decision.status, decision.reason), (Status.FAIL, Reason.PARTIAL_EXECUTION))
        shortfalls = [finding.detail for finding in decision.findings if finding.source == "contract:checks_executed"]
        self.assertTrue(any("'rows'" in detail for detail in shortfalls))

    def test_d_an_edited_population_breaks_the_chain_or_the_manifest_match(self) -> None:
        entries = [copy.deepcopy(entry) for entry in self.base.ledger.entries]
        entries[0]["evidence"]["inputs"][0]["expected_rows"] = 5
        seal = self.base.ledger.seal()
        unsealed = decide(replay(self.base, entries, (seal["ledger_head_sha256"], seal["ledger_length"])))
        (chain,) = [item for item in unsealed.invariants if item.name == "ledger_chain_intact"]
        self.assertIs(chain.holds, False)
        self.assertIn("ENTRY_EDITED: entry 1", chain.detail)
        self.assertEqual(unsealed.status, Status.FAIL)
        resealed = reseal(entries, self.base.result.run_id)
        self.assertEqual(dict(resealed.invocation_ids), {key: key for key in resealed.invocation_ids}, "no seq moved")
        forged = decide(replay(self.base, resealed.entries, (resealed.ledger_head_sha256, resealed.ledger_length)))
        (chain,) = [item for item in forged.invariants if item.name == "ledger_chain_intact"]
        self.assertIs(chain.holds, True)
        (match,) = [item for item in forged.invariants if item.name == "plan_matches_manifest"]
        self.assertIs(match.holds, False)
        self.assertIn("plan.inputs[measurements].expected_rows differs", match.detail)
        self.assertEqual((forged.status, forged.reason), (Status.FAIL, Reason.PROTOCOL_DRIFT))
        self.assertIn("PROTOCOL_DRIFT", [mode.value for mode in forged.failure_modes])

    def test_the_untouched_run_replays_as_pass(self) -> None:
        seal = self.base.ledger.seal()
        decision = decide(replay(self.base, self.base.ledger.entries, (seal["ledger_head_sha256"], seal["ledger_length"])))
        self.assertEqual(decision.status, Status.PASS)
        (match,) = [item for item in decision.invariants if item.name == "plan_matches_manifest"]
        self.assertEqual((match.applicable, match.holds), (True, True))


class LedgerPlanApiTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()

    def body(self) -> dict[str, Any]:
        return {
            "schema": PLAN_SCHEMA,
            "inputs": [{"input_id": "b", "declared_sha256": None}, {"input_id": "a", "declared_sha256": "c" * 64}],
            "checks": [{"check_id": "rows"}],
            "pins": [],
            "controls": [],
        }

    def test_the_plan_must_come_first_and_has_the_entry_shape(self) -> None:
        ledger = Ledger("run-synthetic-plan")
        entry = ledger.plan(self.body())
        self.assertEqual((entry["seq"], entry["input_ids"]), (1, ["a", "b"]))
        self.assertEqual(entry["input_sha256s"], {"a": "c" * 64, "b": None})
        invocation_id = ledger.start(check_id="rows", check_kind="row_count", check_version="1")
        self.assertEqual(invocation_id, invocation_id_for("run-synthetic-plan", 2), "the first STARTED entry is seq 2")
        with self.assertRaises(LedgerError):
            ledger.plan(self.body())
        self.assertEqual(index_invocations(ledger.entries).keys(), {invocation_id}, "the PLAN is no invocation")

    def test_plan_of_refuses_an_ambiguous_ledger(self) -> None:
        ledger = Ledger("run-synthetic-plan")
        ledger.plan(self.body())
        entries = list(ledger.entries)
        self.assertEqual(plan_of(entries), self.body())
        self.assertIsNone(plan_of(entries + [entries[0]]))
        self.assertIsNone(plan_of(entries[1:]))
        self.assertIsNone(plan_of([]))
        doubled = reseal(entries + [entries[0]], "run-synthetic-plan").entries
        self.assertIs(plan_closure(InvariantContext(entries=tuple(doubled))).holds, False)


class ResealTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        self.ledger = Ledger("run-synthetic-reseal")
        self.ledger.plan({"schema": PLAN_SCHEMA, "inputs": [], "checks": [], "pins": [], "controls": []})
        for check_id in ("one", "two", "three"):
            invocation_id = self.ledger.start(check_id=check_id, check_kind="row_count", check_version="1")
            self.ledger.finish(invocation_id, verdict=Status.PASS, reason=Reason.VERIFIED, evidence={"rows": 1})

    def test_reseal_renumbers_re_derives_ids_and_re_links(self) -> None:
        entries = list(self.ledger.entries)
        dropped = entries[:3] + entries[5:]  # remove invocation "two" entirely
        resealed = reseal(dropped, "run-synthetic-reseal")
        self.assertEqual([entry["seq"] for entry in resealed.entries], list(range(1, len(dropped) + 1)))
        verification = verify_chain(
            resealed.entries, resealed.ledger_head_sha256, resealed.ledger_length, run_id="run-synthetic-reseal"
        )
        self.assertTrue(verification.intact, verification.problems)
        old_three = entries[5]["invocation_id"]
        new_three = resealed.invocation_ids[old_three]
        self.assertEqual(new_three, invocation_id_for("run-synthetic-reseal", 4))
        self.assertEqual([entry["invocation_id"] for entry in resealed.entries[3:]], [new_three, new_three])
        self.assertEqual(resealed.ledger_length, 5)
        self.assertEqual(resealed.ledger_head_sha256, resealed.entries[-1]["entry_sha256"])
        self.assertEqual(len(self.ledger.entries), 7, "the sealed ledger itself is untouched")

    def test_the_original_seal_exposes_the_forgery(self) -> None:
        seal = self.ledger.seal()
        resealed = reseal(list(self.ledger.entries)[1:], "run-synthetic-reseal")
        verification = verify_chain(resealed.entries, seal["ledger_head_sha256"], seal["ledger_length"])
        self.assertFalse(verification.intact)

    def test_an_empty_ledger_reseals_to_nothing(self) -> None:
        resealed = reseal((), "run-synthetic-reseal")
        self.assertEqual((resealed.entries, resealed.ledger_head_sha256, resealed.ledger_length), ((), None, 0))

    def test_plan_matches_manifest_needs_both_a_plan_and_an_expectation(self) -> None:
        context = InvariantContext(entries=self.ledger.entries)
        self.assertFalse(plan_matches_manifest(context).applicable)
        expected = plan_of(self.ledger.entries)
        self.assertIs(plan_matches_manifest(InvariantContext(entries=self.ledger.entries, expected_plan=expected)).holds, True)
        other = {**dict(expected or {}), "controls": ["control:comparator"]}
        mismatch = plan_matches_manifest(InvariantContext(entries=self.ledger.entries, expected_plan=other))
        self.assertIs(mismatch.holds, False)
        self.assertIn("plan.controls differs", mismatch.detail)


if __name__ == "__main__":
    unittest.main()
