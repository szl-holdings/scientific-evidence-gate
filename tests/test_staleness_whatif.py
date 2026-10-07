"""Staleness what-if: mutation-testing the staleness detector (extension #22; ARCHITECTURE.md 17.13).

A staleness checker that never reports stale is itself vacuous. ``what_if``
injects a synthetic digest change into one artifact, in memory, and
requires every declared descendant to go STALE_PENDING_REVALIDATION and
the currency assessment to FAIL. The tests also break the detector on
purpose and show the what-if then FAILs with BLIND_SPOT.

Projects are private copies of the synthetic ``fixtures/dependencies``
trees ``current`` (nine nodes, four publication nodes) and ``witnessed``
(six nodes, two publication nodes).
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from _helpers import FIXED_TIME, REPO_ROOT, SRC_DIR, TempDirTestCase

from science_gate import cli
from science_gate._canonical import sha256_canonical
from science_gate.dependencies import (
    GRAPH_STATE_FILE,
    NO_GRAPH_DECLARED,
    UNKNOWN_ARTIFACT,
    WHAT_IF_DOES_NOT_PROVE,
    WHAT_IF_SCHEMA,
    Assessment,
    DependencyGraph,
    GraphError,
    WhatIfOutcome,
    assess,
    cli_what_if,
    load_graph,
    render_what_if,
    what_if,
    what_if_headline,
)
from science_gate.models import ExecutionState, FailureMode, Reason, Status, Validity
from science_gate.receipts import HMAC_KEY_FILE_ENV

FIXTURES = REPO_ROOT / "fixtures" / "dependencies"
GRAPH = "graph/graph.json"
STALE = Validity.STALE_PENDING_REVALIDATION
#: Every declared descendant of source-snapshot in ``current``, sorted, and the publication nodes among them.
CURRENT_DESCENDANTS = (
    "admitted-evidence",
    "analysis-run",
    "conclusion-1",
    "conclusion-2",
    "figure-1",
    "site-means",
    "table-2",
)
CURRENT_PUBLICATION = ["conclusion-1", "conclusion-2", "figure-1", "table-2"]
HEADINGS = [
    "# Staleness what-if: `source-snapshot`",
    "## STATUS",
    "## INJECTED CHANGE",
    "## DECLARED DESCENDANTS",
    "## CURRENCY ASSESSMENT AFTER THE INJECTION",
    "## TRANSITIONS IN MEMORY",
    "## WHAT THIS DOES NOT PROVE",
]


class WhatIfProject(TempDirTestCase):
    """A private copy of ``fixtures/dependencies/current``, with the clock pinned and no signing key."""

    tree = "current"

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop(HMAC_KEY_FILE_ENV, None)
        self.project = self.tmp / "project"
        shutil.copytree(FIXTURES / self.tree, self.project)

    @property
    def manifest_path(self) -> Path:
        return self.project / "manifest.json"

    def read_json(self, relpath: str) -> Any:
        return json.loads((self.project / relpath).read_text(encoding="utf-8"))

    def write_json(self, relpath: str, document: Any) -> None:
        path = self.project / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")

    def snapshot(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.project).as_posix(): path.read_bytes()
            for path in sorted(self.project.rglob("*"))
            if path.is_file()
        }

    def outcomes(self, report: Any) -> dict[str, WhatIfOutcome]:
        return {item.node_id: item.outcome for item in report.descendants}

    def run_cli(self, artifact: str, manifest: Path | None = None) -> tuple[int, list[str]]:
        buffer = io.StringIO()
        arguments = argparse.Namespace(artifact_id=artifact, manifest=str(manifest or self.manifest_path))
        with contextlib.redirect_stdout(buffer):
            code = cli_what_if(arguments)
        return code, buffer.getvalue().splitlines()


def never_marks(self: DependencyGraph, origin: str, event: str, at: str, **_: Any) -> tuple[()]:
    """A staleness walk that marks nothing: the vacuous detector the what-if exists to catch."""
    return ()


def blind_assess(graph: DependencyGraph, detection: Any) -> Assessment:
    """A currency rule that never blocks publication."""
    real = assess(graph, detection)
    return Assessment(Status.PASS, Reason.VERIFIED, (), (), real.publication_block, real.counts)


class AcceptanceTests(WhatIfProject):
    def test_a_leaf_change_marks_every_declared_descendant_and_currency_fails(self) -> None:
        report = what_if(self.manifest_path, "source-snapshot")
        self.assertEqual((report.status, report.reason), (Status.PASS, Reason.VERIFIED))
        self.assertEqual(report.execution_state, ExecutionState.CHECKED)
        self.assertEqual(report.failure_modes, ())
        self.assertEqual(tuple(self.outcomes(report)), CURRENT_DESCENDANTS)
        self.assertEqual(set(self.outcomes(report).values()), {WhatIfOutcome.MARKED})
        for item in report.descendants:
            self.assertEqual((item.prior_state, item.state), (Validity.CURRENT, STALE), item.node_id)
        self.assertEqual(report.counts(), {"declared_descendants": 7, "MARKED": 7, "ALREADY_PENDING": 0,
                                           "DECLARED_BY_PERSON": 0, "NOT_MARKED": 0})
        assessment = report.assessment
        self.assertEqual((assessment["status"], assessment["reason"]), ("FAIL", "SOURCE_MISMATCH"))
        self.assertIn("STALE_DEPENDENCY", assessment["failure_modes"])
        self.assertEqual(assessment["stale_publication_nodes"], CURRENT_PUBLICATION)
        self.assertEqual(assessment["publication_descendants"], CURRENT_PUBLICATION)
        self.assertIs(assessment["holds"], True)
        injection = report.injection
        self.assertEqual((injection["mode"], injection["node"], injection["path"]), ("digest", "source-snapshot",
                                                                                    "data/measurements.csv"))
        recorded = self.read_json(GRAPH)["nodes"][0]["recorded_sha256"]
        self.assertEqual(injection["recorded_sha256"], recorded)
        self.assertNotEqual(injection["injected_sha256"], recorded)
        self.assertEqual(report.transitions[0][0], "source-snapshot")
        self.assertEqual({node_id for node_id, _ in report.transitions}, {"source-snapshot", *CURRENT_DESCENDANTS})

    def test_the_report_is_identified_by_its_content_and_writes_nothing(self) -> None:
        before = self.snapshot()
        report = what_if(self.manifest_path, "source-snapshot")
        self.assertEqual(self.snapshot(), before)
        document = report.to_dict()
        self.assertEqual(document["schema"], WHAT_IF_SCHEMA)
        self.assertRegex(document["what_if_id"], r"^wif-[0-9a-f]{16}$")
        body = {key: value for key, value in document.items() if key != "what_if_id"}
        self.assertEqual(document["what_if_id"], "wif-" + sha256_canonical(body)[:16])
        self.assertEqual(what_if(self.manifest_path, "source-snapshot").to_dict(), document)
        self.assertNotEqual(what_if(self.manifest_path, "study-design").what_if_id, report.what_if_id)
        self.assertEqual(document["at"], FIXED_TIME)
        self.assertEqual(document["does_not_prove"], list(WHAT_IF_DOES_NOT_PROVE))

    def test_no_node_file_is_read(self) -> None:
        (self.project / "figures/figure-1.csv").unlink()  # a real read would make figure-1 UNRESOLVED
        report = what_if(self.manifest_path, "source-snapshot")
        self.assertEqual(self.outcomes(report)["figure-1"], WhatIfOutcome.MARKED)
        self.assertEqual(report.status, Status.PASS)

    def test_a_node_without_descendants_has_nothing_to_test(self) -> None:
        report = what_if(self.manifest_path, "conclusion-2")
        self.assertEqual((report.status, report.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        self.assertEqual(report.execution_state, ExecutionState.NOT_APPLICABLE)
        self.assertEqual((report.descendants, report.injection, report.assessment), ((), None, None))
        self.assertIn("no declared descendants", report.findings[0].detail)

    def test_the_witnessed_project_passes_too(self) -> None:
        project = self.tmp / "witnessed"
        shutil.copytree(FIXTURES / "witnessed", project)
        report = what_if(project / "manifest.json", "source-snapshot")
        self.assertEqual(report.status, Status.PASS)
        self.assertEqual(tuple(self.outcomes(report)), ("analysis-run", "conclusion-1", "figure-1", "site-summary"))
        self.assertEqual(report.assessment["stale_publication_nodes"], ["conclusion-1", "figure-1"])


class BrokenDetectorTests(WhatIfProject):
    """Each test breaks one part of the detector and shows the what-if catches it."""

    def test_a_walk_that_marks_nothing_is_a_blind_spot(self) -> None:
        with mock.patch.object(DependencyGraph, "_mark_descendants", never_marks):
            report = what_if(self.manifest_path, "source-snapshot")
        self.assertEqual((report.status, report.reason), (Status.FAIL, Reason.BLIND_SPOT))
        self.assertIn(FailureMode.DEFECTIVE_VERIFICATION, report.failure_modes)
        self.assertEqual(set(self.outcomes(report).values()), {WhatIfOutcome.NOT_MARKED})
        self.assertIn("blind to them", report.findings[0].detail)

    def test_a_walk_that_stops_early_is_judged_against_the_declared_edges(self) -> None:
        real_levels = DependencyGraph._levels

        def shallow(graph: DependencyGraph, origin: str) -> list[Any]:
            return [item for item in real_levels(graph, origin) if item[1] <= 2]

        with mock.patch.object(DependencyGraph, "_levels", shallow):
            report = what_if(self.manifest_path, "source-snapshot")
        self.assertEqual(len(report.descendants), 7, "the expected set does not come from the walk")
        outcomes = self.outcomes(report)
        missed = sorted(node_id for node_id, outcome in outcomes.items() if outcome is WhatIfOutcome.NOT_MARKED)
        self.assertEqual(missed, ["conclusion-1", "figure-1", "site-means"])
        self.assertEqual((report.status, report.reason), (Status.FAIL, Reason.BLIND_SPOT))

    def test_a_currency_rule_that_would_not_block_is_a_blind_spot(self) -> None:
        with mock.patch("science_gate.dependencies.assess", blind_assess):
            report = what_if(self.manifest_path, "source-snapshot")
        self.assertEqual(set(self.outcomes(report).values()), {WhatIfOutcome.MARKED})
        self.assertIs(report.assessment["holds"], False)
        self.assertEqual((report.status, report.reason), (Status.FAIL, Reason.BLIND_SPOT))
        self.assertIn("would not block", report.findings[0].detail)

    def test_the_cli_exits_1_for_a_blind_detector(self) -> None:
        with mock.patch.object(DependencyGraph, "_mark_descendants", never_marks):
            code, lines = self.run_cli("source-snapshot")
        self.assertEqual(code, 1)
        self.assertTrue(lines[0].startswith("FAIL (BLIND_SPOT) what-if source-snapshot wif-"), lines[0])


class NonWitnessingDescendantTests(WhatIfProject):
    def test_descendants_declared_by_a_person_are_listed_not_blamed(self) -> None:
        document = self.read_json(GRAPH)
        for node in document["nodes"]:
            if node["id"] == "figure-1":
                node["validity"] = "SUPERSEDED"
        self.write_json(GRAPH, document)
        report = what_if(self.manifest_path, "source-snapshot")
        self.assertEqual(self.outcomes(report)["figure-1"], WhatIfOutcome.DECLARED_BY_PERSON)
        self.assertEqual(report.status, Status.PASS)
        self.assertEqual(report.assessment["stale_publication_nodes"], ["conclusion-1", "conclusion-2", "table-2"])

    def test_a_what_if_with_nothing_left_to_mark_abstains_as_vacuous(self) -> None:
        graph = load_graph(self.project, GRAPH)
        graph.impact("source-snapshot")
        graph.save_state()
        report = what_if(self.manifest_path, "source-snapshot")
        self.assertEqual(set(self.outcomes(report).values()), {WhatIfOutcome.ALREADY_PENDING})
        self.assertEqual((report.status, report.reason), (Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE))
        self.assertIn(FailureMode.VACUOUS_PASS, report.failure_modes)
        self.assertEqual(report.state["present"], True)

    def test_a_partly_pending_graph_still_witnesses_the_rest(self) -> None:
        graph = load_graph(self.project, GRAPH)
        graph.impact("table-2")
        graph.save_state()
        report = what_if(self.manifest_path, "source-snapshot")
        outcomes = self.outcomes(report)
        self.assertEqual(outcomes["table-2"], WhatIfOutcome.ALREADY_PENDING)
        self.assertEqual(outcomes["conclusion-2"], WhatIfOutcome.ALREADY_PENDING)
        self.assertEqual(outcomes["conclusion-1"], WhatIfOutcome.MARKED)
        self.assertEqual(report.status, Status.PASS)

    def test_a_fileless_artifact_is_declared_changed(self) -> None:
        document = self.read_json(GRAPH)
        for node in document["nodes"]:
            if node["id"] == "study-design":
                node.update(path=None, recorded_sha256=None)
        self.write_json(GRAPH, document)
        report = what_if(self.manifest_path, "study-design")
        self.assertEqual(report.injection["mode"], "declared_change")
        self.assertIsNone(report.injection["injected_sha256"])
        self.assertEqual(report.status, Status.PASS)
        self.assertEqual(report.assessment["stale_publication_nodes"], ["conclusion-1", "figure-1"])


class CommandLineTests(WhatIfProject):
    def test_headline_blank_line_then_the_markdown_report(self) -> None:
        before = self.snapshot()
        code, lines = self.run_cli("source-snapshot")
        self.assertEqual(code, 0)
        self.assertEqual(self.snapshot(), before)
        report = what_if(self.manifest_path, "source-snapshot").to_dict()
        self.assertEqual(lines[0], what_if_headline(report))
        self.assertEqual(
            lines[0],
            f"PASS (VERIFIED) what-if source-snapshot {report['what_if_id']}: 7 of 7 declared descendant(s) newly "
            "marked STALE_PENDING_REVALIDATION; currency assessment FAIL",
        )
        self.assertEqual(lines[1], "")
        self.assertEqual(lines[2:], render_what_if(report).splitlines())
        self.assertEqual([line for line in lines if line.startswith("#")], HEADINGS)
        self.assertIn("- would block every stale publication descendant: yes", lines)

    def test_the_command_is_wired_into_the_cli(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli.main(["what-if", "source-snapshot", "--manifest", str(self.manifest_path)])
        self.assertEqual(code, 0)
        report = what_if(self.manifest_path, "source-snapshot").to_dict()
        self.assertEqual(buffer.getvalue().splitlines()[0], what_if_headline(report))

    def test_exit_codes_follow_the_status(self) -> None:
        code, lines = self.run_cli("conclusion-2")
        self.assertEqual(code, 2)
        self.assertTrue(lines[0].endswith("no declared descendants, nothing to inject"), lines[0])
        self.assertIn("Nothing was injected: the artifact has no declared descendant.", lines)

    def test_commands_that_cannot_act_exit_3(self) -> None:
        no_graph = self.read_json("manifest.json")
        no_graph.pop("dependencies")
        self.write_json("other-manifest.json", no_graph)
        cases = (
            ("no-such-artifact", self.manifest_path, UNKNOWN_ARTIFACT),
            ("source-snapshot", self.project / "other-manifest.json", NO_GRAPH_DECLARED),
            ("source-snapshot", self.project / "missing.json", "MANIFEST_NOT_FOUND"),
        )
        for artifact, manifest, expected in cases:
            with self.subTest(expected=expected):
                code, lines = self.run_cli(artifact, manifest)
                self.assertEqual((code, len(lines)), (3, 1))
                self.assertTrue(lines[0].startswith("ERROR what-if: "), lines[0])
                self.assertIn(expected, lines[0])
        with self.assertRaises(GraphError):
            what_if(self.manifest_path, "no-such-artifact")
        self.assertFalse((self.project / "graph" / GRAPH_STATE_FILE).exists())

    def test_output_is_identical_under_different_hash_seeds(self) -> None:
        program = (
            "import argparse, sys\n"
            "from science_gate.dependencies import cli_what_if\n"
            "sys.exit(cli_what_if(argparse.Namespace(artifact_id=sys.argv[1], manifest=sys.argv[2])))\n"
        )
        outputs = []
        for seed in ("0", "4242"):
            environment = {key: value for key, value in os.environ.items() if key != HMAC_KEY_FILE_ENV}
            environment.update(
                {
                    "PYTHONPATH": str(SRC_DIR),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONHASHSEED": seed,
                    "SCIENCE_GATE_FIXED_TIME": FIXED_TIME,
                }
            )
            completed = subprocess.run(
                [sys.executable, "-c", program, "source-snapshot", str(self.manifest_path)],
                cwd=self.tmp,
                env=environment,
                capture_output=True,
                text=True,
                timeout=300,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            outputs.append(completed.stdout)
        self.assertEqual(outputs[0], outputs[1])
        self.assertTrue(outputs[0].startswith("PASS (VERIFIED) what-if source-snapshot wif-"), outputs[0])


if __name__ == "__main__":
    unittest.main()
