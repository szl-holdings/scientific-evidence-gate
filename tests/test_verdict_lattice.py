"""The verdict lattice, skip justifications and decide() precedence (section 17.7: #23, #24, D1, D2, G1-G3).

Each tool gap (G1-G3) is pinned by a test that fails against the 0.1.0
engine: G1's header-only run reported one examined row there, G2's
unjustified skip abstained there, and G3's skipped-plus-failed run named the
skip there. All fixtures are synthetic.
"""

from __future__ import annotations

import unittest
from typing import Any

from _helpers import REPO_ROOT, TempDirTestCase
from _project import REVIEWERS, TIME_EVENT, ProjectTestCase, check, reviews_document, time_document

from science_gate.discovery import discover
from science_gate.manifests import load_manifest
from science_gate.models import (
    EMPTY_AGGREGATE_OUTCOME,
    SKIP_JUSTIFICATION_KEY,
    SKIP_JUSTIFICATION_OUTCOMES,
    UNJUSTIFIED_SHORTFALL_OUTCOME,
    CheckResult,
    ExecutionState,
    FailureMode,
    Ratio,
    RatioState,
    Reason,
    SkipJustification,
    Status,
    VerdictLevel,
)
from science_gate.verifier import (
    FALSIFIERS,
    REGISTRY,
    CheckContext,
    CheckOutcome,
    DecisionInputs,
    Finding,
    decide,
    verify,
)

HEADER_ONLY = REPO_ROOT / "fixtures" / "core" / "header-only" / "manifest.json"

# --- synthetic check functions registered only by these tests ----------------


def unlabelled_skip(ctx: CheckContext, spec: Any) -> CheckOutcome:
    """A required checker that did not run and says nothing in the closed vocabulary."""
    return CheckOutcome(ExecutionState.SKIPPED, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, rows_examined=0)


def labelled_not_applicable(label: SkipJustification) -> Any:
    def check_function(ctx: CheckContext, spec: Any) -> CheckOutcome:
        evidence = {SKIP_JUSTIFICATION_KEY: label.value}
        return CheckOutcome(
            ExecutionState.NOT_APPLICABLE, Status.ABSTAIN, Reason.OUT_OF_SCOPE, rows_examined=0, evidence=evidence
        )

    return check_function


def label_on_a_checked_result(ctx: CheckContext, spec: Any) -> CheckOutcome:
    """A label may justify only a skip: on a CHECKED result it is an invalid outcome."""
    evidence = {SKIP_JUSTIFICATION_KEY: SkipJustification.GUARDED_ELSEWHERE.value}
    return CheckOutcome(ExecutionState.CHECKED, Status.ABSTAIN, Reason.UNVERIFIED, rows_examined=1, evidence=evidence)


def raises(ctx: CheckContext, spec: Any) -> CheckOutcome:
    raise RuntimeError("synthetic checker crash")


def always_pass(ctx: CheckContext, spec: Any) -> CheckOutcome:
    """A defective checker that passes whatever it is shown."""
    rows = sum(len(ctx.inputs[input_id].rows or ()) for input_id in spec.inputs)
    return CheckOutcome(ExecutionState.CHECKED, Status.PASS, Reason.VERIFIED, rows_examined=rows, evidence={"rows": rows})


for _label in SkipJustification:
    globals()[f"labelled_{_label.value.lower()}"] = labelled_not_applicable(_label)

LATTICE_REGISTRY = {
    **REGISTRY,
    "unlabelled_skip": f"{__name__}:unlabelled_skip",
    "label_on_checked": f"{__name__}:label_on_a_checked_result",
    "raises": f"{__name__}:raises",
    "always_pass": f"{__name__}:always_pass",
    **{f"labelled_{label.value.lower()}": f"{__name__}:labelled_{label.value.lower()}" for label in SkipJustification},
}


class RatioAndLatticeTests(unittest.TestCase):
    """Extension #23: a typed Ratio and a verdict lattice with a NONE bottom."""

    def test_a_zero_denominator_never_renders_as_zero_or_one_hundred_percent(self) -> None:
        empty = Ratio(0, 0)
        self.assertEqual(empty.state, RatioState.ZERO_DENOMINATOR)
        self.assertIsNone(empty.value)
        self.assertIsNone(empty.decimal)
        self.assertEqual(empty.fraction, "0/0", "the counts stay visible; only the figure is withheld")
        self.assertNotIn(empty.decimal, ("0", "1", "0.0", "1.0"))
        self.assertEqual(Ratio(None, 21).to_dict()["state"], RatioState.UNAVAILABLE.value)

    def test_the_brief_worked_values(self) -> None:
        self.assertEqual(Ratio(72, 100).decimal, "0.72")
        self.assertEqual(Ratio(0, 21).decimal, "0")
        self.assertEqual(Ratio(5, 5).decimal, "1")
        self.assertEqual(Ratio(20, 21).to_dict()["fraction"], "20/21", "never reduced")

    def test_an_empty_aggregate_is_abstain_insufficient_evidence(self) -> None:
        self.assertEqual(EMPTY_AGGREGATE_OUTCOME, (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))


class EmptyAggregateDecisionTests(TempDirTestCase):
    def test_decide_over_nothing_at_all_abstains_and_never_passes(self) -> None:
        # Every count is known and nothing is wrong, but nothing was required and nothing passed.
        self.fixed_clock()
        self.write("data/measurements.csv", "sample_id\nSYN-0001\n")
        manifest = load_manifest(
            self.write_manifest(
                {
                    "schema": "science-gate-manifest/v1",
                    "inputs": [{"id": "measurements", "path": "data/measurements.csv", "format": "csv"}],
                    "checks": [{"id": "rows", "kind": "row_count", "version": "1", "inputs": ["measurements"]}],
                }
            )
        )
        accounting, _ = discover(manifest)
        decision = decide(
            DecisionInputs(
                accounting=accounting,
                declared_checks=None,
                rows_examined=1,
                evidence_manifest=[{"sha256": "a" * 64}],
            )
        )
        self.assertEqual(decision.findings, ())
        self.assertEqual((decision.status, decision.reason), EMPTY_AGGREGATE_OUTCOME)
        self.assertIn(FailureMode.VACUOUS_PASS, decision.failure_modes)
        self.assertEqual(decision.transitions, (), "the join stayed at NONE")


class TransitionLogTests(ProjectTestCase):
    def test_the_run_records_each_rise_of_the_lattice(self) -> None:
        passing = self.run_verify()
        transitions = passing.result.controls["verdict_transitions"]
        self.assertEqual(
            [(item["before"], item["after"], item["reason"]) for item in transitions],
            [("NONE", "PASS", "VERIFIED")],
        )
        self.assertEqual(transitions[0]["source"], "check:columns", "required PASSes join first, in check-id order")
        # A duplicated row FAILs one check: the log rises to FAIL and stops.
        lines = self.data_lines()
        self.write_data("".join(lines + [lines[1]]))
        failing = self.run_verify()
        log = failing.result.controls["verdict_transitions"]
        self.assertEqual(log[-1]["after"], failing.status.value)
        levels = [VerdictLevel(item["after"]) for item in log]
        ranks = [list(VerdictLevel).index(level) for level in levels]
        self.assertEqual(ranks, sorted(set(ranks)), "every logged step rises")
        self.assertIn("check:duplicates", [item["source"] for item in log])


class LatticeProjectCase(ProjectTestCase):
    def verify_with(self, *extra: dict[str, Any]) -> Any:
        self.add_checks(*extra)
        return self.run_verify(registry=LATTICE_REGISTRY, falsifiers=FALSIFIERS)

    def contract(self, run: Any) -> list[Finding]:
        return [finding for finding in run.findings if finding.source == "contract:checks_executed"]


class SkipJustificationTests(LatticeProjectCase):
    """Extension #24 and D1: free text never justifies a skip; a closed label abstains."""

    def test_a_required_skip_without_a_label_is_fail_partial_execution(self) -> None:
        run = self.verify_with(check("skipped", "unlabelled_skip", inputs=()))
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.FAIL, Reason.PARTIAL_EXECUTION, 1))
        (finding,) = self.contract(run)
        self.assertEqual((finding.status, finding.reason, finding.failure_modes), UNJUSTIFIED_SHORTFALL_OUTCOME)
        self.assertIn("'skipped' did not execute: it was SKIPPED, with no closed-vocabulary justification", finding.detail)

    def test_every_label_contributes_its_row_and_none_is_partial_execution(self) -> None:
        for label in SkipJustification:
            with self.subTest(label=label.value):
                run = self.verify_with(check("excused", f"labelled_{label.value.lower()}", inputs=()))
                (finding,) = self.contract(run)
                status, reason, modes = SKIP_JUSTIFICATION_OUTCOMES[label]
                self.assertEqual((finding.status, finding.reason, finding.failure_modes), (status, reason, modes))
                self.assertIs(run.status, Status.ABSTAIN)
                self.assertNotIn(FailureMode.PARTIAL_EXECUTION, run.result.failure_modes)
                self.assertEqual(run.result.counters["checks_justified"], 1)
                self.set_checks(*[item for item in self.manifest()["checks"] if item["id"] != "excused"])

    def test_guarded_elsewhere_requires_human_review(self) -> None:
        run = self.verify_with(check("excused", "labelled_guarded_elsewhere", inputs=()))
        (finding,) = self.contract(run)
        self.assertEqual((finding.status, finding.reason), (Status.ABSTAIN, Reason.REQUIRES_HUMAN_REVIEW))
        self.assertIn(Reason.REQUIRES_HUMAN_REVIEW, run.result.reasons)

    def test_a_label_on_anything_but_a_skipped_abstention_is_an_invalid_outcome(self) -> None:
        run = self.verify_with(check("mislabelled", "label_on_checked", inputs=()))
        result = self.result_of(run, "mislabelled")
        self.assertEqual(result.verdict, Status.ERROR)
        self.assertIn("INVALID_OUTCOME", result.diagnostics[0])
        self.assertEqual(run.status, Status.ERROR)

    def test_built_in_skips_carry_their_labels(self) -> None:
        # The engine's own NOT_APPLICABLE and SKIPPED results are all labelled (17.7).
        (self.project / "snapshots" / "accepted.json").write_text("{broken", encoding="utf-8")
        self.update_manifest(time_sources="time/events.json", summary_claim="claims/summary.json")
        self.write_json("time/events.json", time_document())
        self.add_checks(
            check("timing", "time_source", inputs=()),
            check("reviewers", "reviewer_protocol", inputs=()),
            check("summary", "summary_consistency", inputs=()),
        )
        run = self.run_verify()
        labels = {item.check_id: item.evidence.get(SKIP_JUSTIFICATION_KEY) for item in run.result.checks}
        self.assertEqual(labels["snapshot"], SkipJustification.EVIDENCE_MALFORMED.value)
        self.assertEqual(labels["timing"], SkipJustification.EMPTY_POPULATION.value)
        self.assertEqual(labels["reviewers"], SkipJustification.NOT_DECLARED.value)
        self.assertEqual(labels["summary"], SkipJustification.INPUT_UNAVAILABLE.value)
        self.assertEqual(run.result.counters["checks_justified"], run.result.counters["checks_shortfall"])

    def test_an_input_digest_mismatch_is_labelled_source_rejected(self) -> None:
        self.write_data("".join(self.data_lines()[:-1]), declare_digest=False)
        run = self.run_verify()
        for result in run.result.checks:
            with self.subTest(check=result.check_id):
                self.assertEqual(result.evidence[SKIP_JUSTIFICATION_KEY], SkipJustification.SOURCE_REJECTED.value)
        self.assertEqual((run.status, run.result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))


class PartialInputTests(ProjectTestCase):
    def test_a_partial_input_stays_abstain_partial_execution(self) -> None:
        # D1 leaves inputs alone: requirement 7's PARTIAL input is still ABSTAIN, never FAIL.
        self.update_manifest(limits={"max_rows": 4})
        run = self.run_verify()
        self.assertEqual((run.status, run.result.reason), (Status.ABSTAIN, Reason.PARTIAL_EXECUTION))
        self.assertEqual(run.result.counters["checks_shortfall"], 0, "every check executed over the partial rows")


class G1PopulationTests(ProjectTestCase):
    """G1: run-level rows_examined counts only distinct data rows of declared inputs."""

    def test_a_header_only_input_examines_zero_rows_even_beside_a_passing_pin_comparison(self) -> None:
        # Failing first: 0.1.0 counted the summary's one pin comparison as a row and reported 1.
        run = verify(HEADER_ONLY)
        self.assertEqual(run.result.counters["rows_examined"], 0)
        summary = self.result_of(run, "summary")
        self.assertEqual((summary.verdict, summary.rows_examined), (Status.PASS, 1), "its own figure is its own")
        self.assertIn("contract:rows_examined", [finding.source for finding in run.findings])
        (rows_finding,) = [finding for finding in run.findings if finding.source == "contract:rows_examined"]
        self.assertIn("rows_examined=0 (distinct data rows of declared inputs)", rows_finding.detail)
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, 2))
        self.assertIn(FailureMode.VACUOUS_PASS, run.result.failure_modes)
        self.assertNotIn(FailureMode.PARTIAL_EXECUTION, run.result.failure_modes)
        self.assertNotIn(Reason.PARTIAL_EXECUTION, run.result.reasons)

    def test_verdicts_and_events_are_never_rows(self) -> None:
        self.write_json("reviews/verdicts.json", reviews_document(*REVIEWERS))
        self.write_json("time/events.json", time_document(TIME_EVENT))
        self.update_manifest(
            reviews={"required_reviewers": REVIEWERS, "verdicts": "reviews/verdicts.json"},
            time_sources="time/events.json",
        )
        self.set_checks(check("reviewers", "reviewer_protocol", inputs=()), check("timing", "time_source", inputs=()))
        run = self.run_verify()
        self.assertEqual({item.verdict for item in run.result.checks}, {Status.PASS})
        self.assertEqual(run.result.counters["rows_examined"], 0)
        self.assertEqual((run.status, run.result.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))

    def test_each_row_counts_once_however_many_checks_read_it(self) -> None:
        run = self.run_verify()
        self.assertEqual(run.result.counters["rows_examined"], 6)
        self.assertGreater(sum(item.rows_examined for item in run.result.checks), 6)
        (invariant,) = [item for item in run.result.invariants if item.name == "pass_requires_examined_rows"]
        self.assertEqual(invariant.detail, "rows_examined=6 (distinct data rows of declared inputs)")


class G2ShortfallTests(LatticeProjectCase):
    """G2: the corpus entries vacuous-pass, coverage-debt and partial-execution, re-baselined."""

    def test_vacuous_pass_is_abstain_insufficient_evidence(self) -> None:
        run = verify(HEADER_ONLY)
        (finding,) = self.contract(run)
        self.assertEqual(
            (finding.status, finding.reason, finding.failure_modes),
            (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, (FailureMode.VACUOUS_PASS,)),
        )

    def test_coverage_debt_is_abstain_out_of_scope(self) -> None:
        document = self.manifest()
        del document["accepted_snapshot"]
        self.save_manifest(document)
        run = self.run_verify()
        snapshot = self.result_of(run, "snapshot")
        self.assertEqual(snapshot.execution_state, ExecutionState.NOT_APPLICABLE)
        self.assertEqual(snapshot.evidence[SKIP_JUSTIFICATION_KEY], SkipJustification.NOT_DECLARED.value)
        self.assertEqual((run.status, run.result.reason), (Status.ABSTAIN, Reason.OUT_OF_SCOPE))

    def test_partial_execution_is_fail(self) -> None:
        run = self.verify_with(check("skipped", "unlabelled_skip", inputs=()))
        self.assertEqual((run.status, run.result.reason), (Status.FAIL, Reason.PARTIAL_EXECUTION))
        self.assertEqual((run.result.counters["checks_shortfall"], run.result.counters["checks_justified"]), (1, 0))

    def test_an_error_adds_no_contract_finding(self) -> None:
        run = self.verify_with(check("crash", "raises", inputs=()))
        self.assertEqual(self.contract(run), [])
        self.assertEqual(run.result.counters["checks_shortfall"], 0)
        self.assertEqual((run.status, run.result.reason), (Status.ERROR, Reason.PROTOCOL_BROKEN))


class G3PrecedenceTests(LatticeProjectCase):
    """G3 and 17.7: ERROR > FAIL > ABSTAIN > PASS, and a content FAIL outranks an unexplained shortfall."""

    def test_a_content_failure_names_the_reason_over_an_earlier_shortfall(self) -> None:
        # The shortfall is gathered (contract) before the content failure (an invariant), so first-in-order
        # alone would name PARTIAL_EXECUTION. G3: at FAIL, a content failure names the reason.
        self.set_checks(*[item for item in self.manifest()["checks"] if item["id"] != "rows"])
        self.set_expected_rows_to(7)
        run = self.verify_with(check("skipped", "unlabelled_skip", inputs=()))
        order = [finding.source for finding in run.findings if finding.status is Status.FAIL]
        self.assertEqual(order, ["contract:checks_executed", "invariant:input_accounting_closure"])
        self.assertEqual((run.status, run.result.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))
        self.assertIn(Reason.PARTIAL_EXECUTION, run.result.reasons)

    def test_a_skipped_required_check_alone_is_fail_partial_execution(self) -> None:
        run = self.verify_with(check("skipped", "unlabelled_skip", inputs=()))
        self.assertEqual((run.status, run.result.reason), (Status.FAIL, Reason.PARTIAL_EXECUTION))

    def test_error_outranks_fail(self) -> None:
        run = self.verify_with(check("skipped", "unlabelled_skip", inputs=()), check("crash", "raises", inputs=()))
        self.assertEqual((run.status, run.result.reason), (Status.ERROR, Reason.PROTOCOL_BROKEN))
        self.assertIn(Reason.PARTIAL_EXECUTION, run.result.reasons)

    def test_fail_outranks_abstain(self) -> None:
        run = self.verify_with(
            check("excused", "labelled_not_declared", inputs=()), check("skipped", "unlabelled_skip", inputs=())
        )
        self.assertEqual((run.status, run.result.reason), (Status.FAIL, Reason.PARTIAL_EXECUTION))
        self.assertIn(Reason.OUT_OF_SCOPE, run.result.reasons)

    def test_reasons_are_listed_in_gathering_order_and_deduplicated(self) -> None:
        checks = (
            CheckResult("a", "row_count", "1", True, ExecutionState.CHECKED, Status.ABSTAIN, Reason.UNVERIFIED, rows_examined=1),
            CheckResult("b", "row_count", "1", True, ExecutionState.CHECKED, Status.FAIL, Reason.SOURCE_MISMATCH, rows_examined=1),
        )
        run = self.run_verify()
        decision = decide(
            DecisionInputs(
                accounting=run.result.accounting,
                checks=checks,
                declared_checks={"a": True, "b": True},
                rows_examined=6,
                evidence_manifest=[{"sha256": "a" * 64}],
            )
        )
        self.assertEqual(decision.status, Status.FAIL)
        self.assertEqual(decision.reason, Reason.SOURCE_MISMATCH)
        self.assertEqual(decision.reasons[:2], (Reason.UNVERIFIED, Reason.SOURCE_MISMATCH))
        self.assertEqual(len(decision.reasons), len(set(decision.reasons)))

    def set_expected_rows_to(self, count: int) -> None:
        document = self.manifest()
        document["inputs"][0]["expected_rows"] = count
        self.save_manifest(document)


class BlindSpotSplitTests(ProjectTestCase):
    """D2: BLIND_SPOT is FAIL when a miss is proven and ABSTAIN when coverage is unknown."""

    def test_unknown_coverage_abstains(self) -> None:
        no_generator = {kind: target for kind, target in FALSIFIERS.items() if kind != "row_count"}
        unknown = self.run_verify(falsifiers=no_generator)
        rows = self.result_of(unknown, "rows")
        self.assertEqual((rows.verdict, rows.reason), (Status.ABSTAIN, Reason.BLIND_SPOT))
        self.assertIn(FailureMode.VACUOUS_PASS, rows.failure_modes)
        self.assertEqual((unknown.status, unknown.result.reason, unknown.exit_code), (Status.ABSTAIN, Reason.BLIND_SPOT, 2))

    def test_a_proven_miss_fails(self) -> None:
        self.add_checks(check("blind", "always_pass"))
        falsifiers = {**FALSIFIERS, "always_pass": "science_gate.verifier:falsify_duplicate_rows"}
        proven = self.run_verify(registry=LATTICE_REGISTRY, falsifiers=falsifiers)
        blind = self.result_of(proven, "blind")
        self.assertEqual(blind.evidence["falsification"], "REFUTED")
        self.assertEqual((blind.verdict, blind.reason), (Status.FAIL, Reason.BLIND_SPOT))
        self.assertIn(FailureMode.DEFECTIVE_VERIFICATION, blind.failure_modes)
        self.assertEqual((proven.status, proven.result.reason, proven.exit_code), (Status.FAIL, Reason.BLIND_SPOT, 1))


if __name__ == "__main__":
    unittest.main()
