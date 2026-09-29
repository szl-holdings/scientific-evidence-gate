"""report.html, the evidence-boundary hologram (ARCHITECTURE.md section 12).

The renderer is a view of ``run.json``. These tests pin down what the page
must never do:

* make missing evidence look present;
* present a PASS that its own figures contradict;
* run code or contact any host;
* render the same document differently.

Every document is synthetic. It comes from verifying the invented starter
project (or the repository's synthetic fixtures), and some tests then edit
it.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from unittest import mock

from _helpers import FIXED_TIME, REPO_ROOT, SRC_DIR

from science_gate import _html
from science_gate._html import NO_SENSITIVITY_SENTENCE, VALIDITY_LABEL, render
from science_gate.cli import scaffold_project
from science_gate.receipts import HMAC_KEY_FILE_ENV, build_run_receipt
from science_gate.reports import REPORT_HTML, REPORT_MD, RUN_JSON, report_run_dir, run_document, write_run
from science_gate.verifier import VerificationRun, verify

EMPTY_MANIFEST = REPO_ROOT / "fixtures" / "core" / "empty" / "manifest.json"
VISUALS = {"hologram", "accounting", "lattice", "invariants", "ledger"}

#: Markup that would run code, load a resource or break out of an attribute if it were not escaped.
HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(1)>"\' onmouseover="alert(1)" &amp; </svg></table>'
#: A wrong-typed value that contains every JSON kind the renderer might trip over.
JUNK = [None, 1, "x", {"k": []}, [2], True]


# ---------------------------------------------------------------------------
# Synthetic runs, built once per module
# ---------------------------------------------------------------------------

RUNS: dict[str, VerificationRun] = {}
DOCS: dict[str, dict[str, Any]] = {}
_PAGES: dict[str, str] = {}
_WORKSPACE: list[Path] = []


def _document(run: VerificationRun) -> dict[str, Any]:
    """The run.json document exactly as ``verify`` would write it, unsigned."""
    seal = run.ledger.seal()
    receipt = build_run_receipt(
        run.result, ledger_head_sha256=seal["ledger_head_sha256"], ledger_length=seal["ledger_length"], environ={}
    )
    return run_document(run, receipt)


def setUpModule() -> None:
    environment = mock.patch.dict(os.environ, {"SCIENCE_GATE_FIXED_TIME": FIXED_TIME})
    environment.start()
    unittest.addModuleCleanup(environment.stop)
    os.environ.pop(HMAC_KEY_FILE_ENV, None)
    workspace = Path(tempfile.mkdtemp(prefix="science-gate-html-")).resolve()
    unittest.addModuleCleanup(shutil.rmtree, workspace, ignore_errors=True)
    _WORKSPACE.append(workspace)

    def project(name: str) -> Path:
        root = workspace / name
        scaffold_project(root)
        return root

    RUNS["pass"] = verify(project("pass") / "manifest.json")
    RUNS["empty"] = verify(EMPTY_MANIFEST)

    missing = project("missing")
    (missing / "data" / "measurements.csv").unlink()
    RUNS["missing"] = verify(missing / "manifest.json")

    changed = project("hash")
    data = changed / "data" / "measurements.csv"
    data.write_text(data.read_text(encoding="utf-8").replace("12.40", "12.41"), encoding="utf-8")
    RUNS["hash"] = verify(changed / "manifest.json")

    broken = project("error")
    (broken / "manifest.json").write_text('{"schema": "not-a-science-gate-manifest/v0"}', encoding="utf-8")
    RUNS["error"] = verify(broken / "manifest.json")

    DOCS.update({name: _document(run) for name, run in RUNS.items()})


def doc(name: str = "pass") -> dict[str, Any]:
    """A private deep copy, so a test can edit it freely."""
    return copy.deepcopy(DOCS[name])


def page_source(name: str) -> str:
    """The rendered page of an unedited scenario (cached: rendering redacts every value and is not free)."""
    if name not in _PAGES:
        _PAGES[name] = render(DOCS[name])
    return _PAGES[name]


class Page(HTMLParser):
    """A rendered page, parsed: its elements, its nesting problems, and the text inside marked elements.

    Text is captured for every element with an ``id`` (key ``#id``) and every
    ``data-visual`` or ``data-equivalent-of`` element (key ``name=value``).
    """

    VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"})

    def __init__(self, source: str) -> None:
        super().__init__(convert_charrefs=True)
        self.source = source
        self.elements: list[tuple[str, dict[str, str | None]]] = []
        self.problems: list[str] = []
        self.captured: dict[str, list[str]] = {}
        self._open: list[tuple[str, list[str]]] = []
        self.feed(source)
        self.close()
        if self._open:
            self.problems.append("unclosed: " + ", ".join(tag for tag, _ in self._open))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        self.elements.append((tag, attributes))
        if tag in self.VOID:
            return
        keys = [f"#{attributes['id']}"] if attributes.get("id") else []
        keys += [f"{name}={attributes[name]}" for name in ("data-visual", "data-equivalent-of") if attributes.get(name)]
        self._open.append((tag, keys))

    def handle_endtag(self, tag: str) -> None:
        if not self._open or self._open[-1][0] != tag:
            self.problems.append(f"unexpected </{tag}>")
            return
        self._open.pop()

    def handle_data(self, data: str) -> None:
        for _, keys in self._open:
            for key in keys:
                self.captured.setdefault(key, []).append(data)

    def text(self, key: str) -> str:
        return " ".join(" ".join(self.captured.get(key, [])).split())

    def tags(self, name: str) -> list[dict[str, str | None]]:
        return [attributes for tag, attributes in self.elements if tag == name]


def svg_of(source: str, key: str) -> str:
    """The markup of one figure's SVG, found by its title id."""
    start = source.index(f'aria-labelledby="{key}-title {key}-desc"')
    return source[start : source.index("</svg>", start)]


def planes(document: dict[str, Any]) -> tuple[Any, Any]:
    return _html._planes(document, _html._invariant_rows(document), _html._lattice_rows(document))


def states(plane: Any) -> dict[str, str]:
    return {facet.name: facet.state for facet in plane.facets}


def gaps(document: dict[str, Any]) -> list[str]:
    return _html._pass_contract_gaps(document, _html._lattice_rows(document), _html._invariant_rows(document))


# ---------------------------------------------------------------------------
# The page as a whole
# ---------------------------------------------------------------------------


class SelfContainedPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.page = Page(page_source("pass"))

    def test_page_is_one_complete_well_nested_document(self) -> None:
        source = self.page.source
        self.assertTrue(source.startswith('<!doctype html>\n<html lang="en">'))
        self.assertTrue(source.endswith("</html>\n"))
        self.assertEqual(self.page.problems, [])
        self.assertEqual(len(self.page.tags("style")), 1)
        self.assertIn({"charset": "utf-8"}, self.page.tags("meta"))

    def test_nothing_can_run_or_load(self) -> None:
        """No script, font, image, frame or form; no event handler; no reference outside the page."""
        forbidden_tags = {"script", "link", "img", "image", "use", "iframe", "object", "embed", "form", "base",
                          "audio", "video", "source", "foreignobject"}
        forbidden_attributes = {"src", "srcset", "action", "formaction", "xlink:href", "style", "background", "ping"}
        for source in (page_source("pass"), render(DOCS["pass"], mutation_report(detected_records()))):
            page = Page(source)
            self.assertFalse(forbidden_tags & {tag for tag, _ in page.elements})
            for tag, attributes in page.elements:
                for name, value in attributes.items():
                    self.assertFalse(name.startswith("on"), (tag, name))
                    self.assertNotIn(name, forbidden_attributes, tag)
                    if name == "href":
                        self.assertTrue(str(value).startswith("#"), value)
            self.assertNotIn("://", source)
            self.assertNotIn("@import", source)
            self.assertNotIn("@font-face", source)
            self.assertEqual([ref for ref in re.findall(r"url\(([^)]*)\)", source) if not ref.startswith("#")], [])

    def test_content_security_policy_forbids_scripts_and_every_request(self) -> None:
        metas = self.page.tags("meta")
        (policy,) = [meta["content"] for meta in metas if meta.get("http-equiv") == "Content-Security-Policy"]
        self.assertIn("default-src 'none'", policy)
        self.assertIn("style-src 'unsafe-inline'", policy)
        self.assertNotIn("script-src", policy)

    def test_colors_are_variables_with_light_and_dark_themes(self) -> None:
        css = self.page.source.split("<style>", 1)[1].split("</style>", 1)[0]
        self.assertIn("@media (prefers-color-scheme:dark)", css)
        self.assertIn(':root[data-theme="dark"]', css)
        self.assertIn("--accent:#2a78d6", css)
        self.assertIn("--accent:#3987e5", css)
        self.assertIn("--void:", css)
        self.assertIn({"name": "color-scheme", "content": "light dark"}, self.page.tags("meta"))

    def test_every_visual_has_a_text_equivalent(self) -> None:
        visuals = {attributes["data-visual"] for _, attributes in self.page.elements if attributes.get("data-visual")}
        equivalents = {
            attributes["data-equivalent-of"]
            for _, attributes in self.page.elements
            if attributes.get("data-equivalent-of")
        }
        self.assertEqual(visuals, VISUALS)
        self.assertLessEqual(visuals, equivalents)
        for visual in visuals:
            self.assertTrue(self.page.text(f"data-equivalent-of={visual}"), visual)

    def test_every_figure_is_labelled_for_assistive_technology(self) -> None:
        for svg in self.page.tags("svg"):
            if svg.get("aria-hidden") == "true":
                continue
            self.assertEqual(svg.get("role"), "img")
            for label_id in str(svg.get("aria-labelledby")).split():
                self.assertTrue(self.page.text(f"#{label_id}"), label_id)

    def test_navigation_links_point_at_sections_on_the_page(self) -> None:
        ids = {attributes.get("id") for _, attributes in self.page.elements}
        targets = [str(link["href"])[1:] for link in self.page.tags("a")]
        self.assertTrue(targets)
        self.assertLessEqual(set(targets), ids)

    def test_module_source_is_ascii(self) -> None:
        """Invisible or bidi characters written literally in the module's own patterns would be unreviewable."""
        Path(_html.__file__).read_bytes().decode("ascii")


# ---------------------------------------------------------------------------
# The hologram: three planes, lit only by evidence
# ---------------------------------------------------------------------------


class HologramTests(unittest.TestCase):
    def validity_group(self, source: str) -> str:
        start = source.index('<g class="plane plane-validity">')
        return source[start : source.index("</g>", start)]

    def test_verified_run_lights_integrity_and_performance(self) -> None:
        integrity, performance = planes(doc())
        self.assertEqual(
            states(integrity),
            {
                "Input digests": "LIT",
                "Declared digests": "LIT",
                "Ledger sealed": "LIT",
                "Hash chain": "LIT",
                "Execution trace": "LIT",
                "Evidence manifest": "LIT",
                "Receipt": "LIT",
                "Signature": "DARK",
                "Re-verification": "DARK",
            },
        )
        self.assertEqual(set(states(performance).values()), {"LIT"})
        self.assertIn("reaches Integrity and Performance", Page(page_source("pass")).text("#hologram-desc"))

    def test_scientific_validity_is_always_dark_and_labelled(self) -> None:
        brightest = doc()
        brightest["receipt"]["signature_state"] = "SIGNED_HMAC_SHA256"
        brightest["reverification"] = {"ok": True, "receipt": {"signature_verified": True}, "ledger": {"intact": True}}
        self.assertEqual(set(states(planes(brightest)[0]).values()), {"LIT"})
        for document in (brightest, {}, doc("error")):
            source = render(document)
            group = self.validity_group(source)
            self.assertIn('class="plane-void"', group)
            self.assertNotIn("tile", group)
            self.assertNotIn("plane-fill", group)
            self.assertIn("NOT ESTABLISHED", group)
            self.assertIn("by this tool", group)
            page = Page(source)
            self.assertIn(f"Scientific validity {VALIDITY_LABEL}", page.text("data-equivalent-of=hologram"))
            self.assertIn("never reaches scientific validity", page.text("#hologram-desc"))

    def test_a_document_with_no_evidence_lights_nothing(self) -> None:
        for plane in planes({}):
            self.assertEqual(set(states(plane).values()), {"DARK"}, plane.title)
        source = render({})
        self.assertNotIn('class="beam"', source)
        self.assertIn("reaches no plane", Page(source).text("#hologram-desc"))

    def test_hash_mismatch_breaks_the_integrity_plane(self) -> None:
        integrity, _ = planes(doc("hash"))
        self.assertEqual(states(integrity)["Declared digests"], "BROKEN")
        self.assertIn('class="plane-edge broken"', page_source("hash"))

    def test_empty_input_leaves_the_evaluation_dark(self) -> None:
        """Requirement 1 as the page shows it: an empty input examines nothing, so nothing is lit for it."""
        _, performance = planes(doc("empty"))
        self.assertEqual(states(performance)["Rows examined"], "DARK")
        self.assertEqual(states(performance)["Required checks executed"], "DARK")
        self.assertEqual(states(performance)["Required checks passed"], "DARK")

    def test_signature_and_reverification_facets(self) -> None:
        signed = doc()
        signed["receipt"]["signature_state"] = "SIGNED_HMAC_SHA256"
        self.assertEqual(states(planes(signed)[0])["Signature"], "LIT")
        signed["reverification"] = {"ok": True, "receipt": {"signature_verified": None}, "ledger": {"intact": True}}
        integrity = states(planes(signed)[0])
        self.assertEqual(integrity["Signature"], "PARTIAL")
        self.assertEqual(integrity["Re-verification"], "LIT")
        failed = doc()
        failed["reverification"] = {"ok": False, "problems": ["synthetic problem"], "ledger": {"intact": False}}
        integrity = states(planes(failed)[0])
        self.assertEqual(integrity["Hash chain"], "BROKEN")
        self.assertEqual(integrity["Re-verification"], "BROKEN")


# ---------------------------------------------------------------------------
# Accounting funnel
# ---------------------------------------------------------------------------


class AccountingTests(unittest.TestCase):
    COUNTERS = ("expected", "discovered", "opened", "parsed", "examined",
                "admitted", "excluded", "deferred", "unresolved", "failed")

    def test_unknown_counts_are_unknown_never_zero(self) -> None:
        source = page_source("error")
        for name in self.COUNTERS:
            self.assertIn(f"<td>{name}</td><td>unknown</td>", source)
        funnel = svg_of(source, "accounting")
        self.assertGreaterEqual(funnel.count(">unknown<"), 5)
        self.assertIn('<div class="stat-value unknown">unknown</div>', source)
        self.assertIn("Closure not evaluable", source)
        self.assertNotIn("Closure holds", source)

    def test_closure_without_an_independent_source_is_never_shown_as_holding(self) -> None:
        document = doc()
        observed = {"source": "OBSERVED", "holds": None, "expected": None, "accounted": 1}
        document["accounting"]["closure"] = dict(observed)
        document["accounting"]["inputs"][0]["closure"] = dict(observed)
        source = render(document)
        self.assertNotIn("Closure holds", source)
        self.assertIn("Closure not evaluable", source)
        _, performance = planes(document)
        self.assertEqual(states(performance)["Input closure"], "DARK")
        self.assertEqual(states(performance)["Row closures"], "DARK")

    def test_broken_closure_is_shown_broken(self) -> None:
        document = doc()
        document["accounting"]["inputs"][0]["closure"] = {"source": "INDEPENDENT", "holds": False, "expected": 7,
                                                          "accounted": 6}
        self.assertIn("Closure BROKEN \u00b7 6 accounted of 7 expected", render(document))
        self.assertEqual(states(planes(document)[1])["Row closures"], "BROKEN")

    def test_missing_required_input_stays_visible(self) -> None:
        """Requirement 6 as the page shows it: the missing file keeps its row and its state."""
        page = Page(page_source("missing"))
        self.assertIn("measurements", page.text("#inputs"))
        self.assertIn("MISSING", page.text("#inputs"))
        self.assertIn("0 of 6 \u00b7 MISSING", svg_of(page.source, "accounting"))
        facet = [item for item in planes(doc("missing"))[1].facets if item.name == "Required inputs parsed"][0]
        self.assertEqual((facet.state, facet.detail), ("DARK", "0 of 1 required input(s) PARSED; measurements MISSING"))


# ---------------------------------------------------------------------------
# Check lattice
# ---------------------------------------------------------------------------


class LatticeTests(unittest.TestCase):
    def cells(self, document: dict[str, Any]) -> dict[str, tuple[str, str, str]]:
        return {
            row.check_id: (row.expected.label, row.executed.label, row.terminal.label)
            for row in _html._lattice_rows(document)
        }

    def test_each_declared_check_is_a_lattice_row(self) -> None:
        cells = self.cells(doc())
        self.assertEqual(set(cells), {"rows", "columns", "duplicates", "snapshot", "values", "counts"})
        self.assertEqual(set(cells.values()), {("REQUIRED", "CHECKED", "PASS")})
        table = Page(page_source("pass")).text("data-equivalent-of=lattice")
        for check_id in cells:
            self.assertIn(check_id, table)

    def test_a_required_checker_that_did_not_run_stays_visible(self) -> None:
        """Requirement 4 as the page shows it: the declared check keeps its row, and a PASS becomes unsupported."""
        document = doc()
        document["checks"] = [item for item in document["checks"] if item["check_id"] != "snapshot"]
        self.assertEqual(self.cells(document)["snapshot"], ("REQUIRED", "NO RESULT", "NO RESULT"))
        self.assertIn("required check snapshot has no recorded result", gaps(document))
        self.assertIn('id="contradiction-heading"', render(document))

    def test_a_verdict_without_an_invocation_is_marked(self) -> None:
        """Requirement 21: every verdict must point to an invocation, and the page shows one that does not."""
        document = doc()
        document["checks"][0]["invocation_id"] = None
        check_id = document["checks"][0]["check_id"]
        self.assertEqual(self.cells(document)[check_id][2], "NO INVOCATION")
        self.assertIn(f"required check {check_id} has no invocation", gaps(document))

    def test_partial_execution_cannot_look_complete(self) -> None:
        """Requirement 7 as the page shows it."""
        source = page_source("empty")
        self.assertIn('<div class="stat-value">0 / 3</div>', source)
        self.assertIn(">0 checked<", svg_of(source, "lattice"))
        self.assertEqual(set(self.cells(doc("empty")).values()), {("REQUIRED", "NOT_APPLICABLE", "ABSTAIN")})
        partial = doc()
        partial["checks_executed"] = 5
        self.assertIn("checks_executed is 5 but checks_expected is 6", gaps(partial))


# ---------------------------------------------------------------------------
# Invariant ring
# ---------------------------------------------------------------------------


class InvariantRingTests(unittest.TestCase):
    def test_one_segment_per_invariant(self) -> None:
        ring = svg_of(page_source("pass"), "invariants")
        self.assertEqual(ring.count("<title>"), 10)  # one tooltip per segment; the figure's own title has an id
        self.assertIn(">10 of 10<", ring)

    def test_contract_invariants_missing_from_the_document_are_listed(self) -> None:
        document = doc()
        document["invariants"] = document["invariants"][:3]
        rows = _html._invariant_rows(document)
        self.assertEqual(len(rows), 10)
        self.assertEqual(sum(1 for row in rows if row.state == "NOT_RECORDED"), 7)
        page = Page(render(document))
        self.assertEqual(page.text("data-equivalent-of=invariants").count("NOT_RECORDED"), 7)
        self.assertIn("7 not recorded", svg_of(page.source, "invariants"))

    def test_a_violated_invariant_is_shown_violated(self) -> None:
        document = doc()
        (chain,) = [item for item in document["invariants"] if item["name"] == "ledger_chain_intact"]
        chain["holds"] = False
        (row,) = [item for item in _html._invariant_rows(document) if item.name == "ledger_chain_intact"]
        self.assertEqual(row.state, "VIOLATED")
        self.assertEqual(states(planes(document)[0])["Hash chain"], "BROKEN")
        self.assertIn(">1 violated<", svg_of(render(document), "invariants"))


# ---------------------------------------------------------------------------
# Ledger chain strip
# ---------------------------------------------------------------------------


class LedgerChainTests(unittest.TestCase):
    def test_invocation_starts_sit_where_the_ledger_started_them(self) -> None:
        """Requirements 21 and 22: each verdict is placed on the chain at its own STARTED entry."""
        entries = RUNS["pass"].ledger.entries
        started = {entry["invocation_id"]: entry["seq"] for entry in entries if entry["result"] == "STARTED"}
        view = _html._ledger_view(doc())
        placed = {check["invocation_id"]: seq for seq, checks in view.starts.items() for check in checks}
        self.assertEqual(placed, started)
        self.assertEqual((view.unplaced, view.without_invocation), ((), ()))
        self.assertIn(DOCS["pass"]["ledger_head_sha256"], page_source("pass"))

    def test_an_invocation_id_from_elsewhere_is_not_placeable(self) -> None:
        document = doc()
        document["checks"][0]["invocation_id"] = "inv-000000000000"
        self.assertEqual(len(_html._ledger_view(document).unplaced), 1)
        self.assertIn("Not placeable", Page(render(document)).text("#ledger"))

    def test_a_long_ledger_is_elided_only_in_the_drawing(self) -> None:
        document = doc()
        document["ledger_length"] = 1000
        strip = svg_of(render(document), "ledger")
        self.assertIn("\u22ef 960 \u22ef", strip)
        self.assertIn("1000 entries", strip)

    def test_an_absurd_ledger_length_is_not_hashed_through(self) -> None:
        document = doc()
        document["ledger_length"] = 10**12
        self.assertFalse(_html._ledger_view(document).derived)
        self.assertIn("not derived", render(document))

    def test_an_empty_ledger_is_drawn_empty(self) -> None:
        self.assertIn(">empty ledger<", svg_of(page_source("error"), "ledger"))

    def test_a_negative_ledger_length_is_invalid_not_empty(self) -> None:
        document = doc()
        document["ledger_length"] = -3
        strip = svg_of(render(document), "ledger")
        self.assertIn(">invalid length<", strip)
        self.assertNotIn("empty ledger", strip)
        self.assertEqual(states(planes(document)[0])["Ledger sealed"], "BROKEN")


# ---------------------------------------------------------------------------
# Mutation constellation
# ---------------------------------------------------------------------------


def mutation_record(mutation_id: str, *, state: str = "CHECKED", detected: bool | None = True,
                    applicable: bool = True) -> dict[str, Any]:
    return {
        "mutation_id": mutation_id,
        "description": f"synthetic mutation {mutation_id}",
        "expected_result": "not PASS",
        "actual_result": "FAIL" if detected else "PASS",
        "applicable": applicable,
        "execution_state": state,
        "expected_detector": "row_count",
        "detecting_invariants_fired": ["row_count"] if detected else [],
        "detected": detected,
        "blind_spot": detected is False and state == "CHECKED",
        "diagnostics": [],
    }


def detected_records() -> list[dict[str, Any]]:
    return [
        mutation_record("M01_empty_input"),
        mutation_record("M03_deleted_accepted_row"),
        mutation_record("M20_metadata_change_under_unchanged_pass_summary", detected=False),
    ]


def mutation_report(records: list[dict[str, Any]], **fields: Any) -> dict[str, Any]:
    report: dict[str, Any] = {"baseline": {"status": "PASS"}, "mutations": records}
    report.update(fields)
    return report


class MutationConstellationTests(unittest.TestCase):
    def test_detections_and_blind_spots_are_separate_constellations(self) -> None:
        report = mutation_report(detected_records(), sensitivity={"fraction": "2/3", "decimal": "0.667"},
                                 executed_mutations=3, detected_mutations=2, escaped_mutations=1)
        page = Page(render(DOCS["pass"], report))
        stars = svg_of(page.source, "mutations")
        self.assertIn("DETECTED \u00b7 2", stars)
        self.assertIn("BLIND SPOTS \u00b7 1", stars)
        self.assertIn('class="star-halo t-critical"', stars)
        self.assertIn("2/3", page.text("#mutations"))
        self.assertIn("BLIND_SPOT", page.text("data-equivalent-of=mutations"))
        self.assertIn("mutations", {attributes.get("data-visual") for _, attributes in page.elements})

    def test_skipped_and_not_applicable_mutations_are_never_detections(self) -> None:
        """Requirement 27, including records that claim a detection they could not have made."""
        records = detected_records() + [
            mutation_record("M04_duplicate_row", state="SKIPPED"),
            mutation_record("M05_duplicate_reviewer_verdict", applicable=False),
            mutation_record("M06_missing_required_reviewer", state="NOT_APPLICABLE", detected=None),
        ]
        view = _html._mutation_view(mutation_report(records))
        self.assertEqual([item.short for item in view.group("DETECTED")], ["M01", "M03"])
        self.assertEqual(view.tallies["detected_mutations"], 2)
        self.assertEqual(view.tallies["executed_mutations"], 3)
        source = render(DOCS["pass"], mutation_report(records))
        self.assertIn("NOT EXECUTED \u00b7 3", svg_of(source, "mutations"))
        table = Page(source).text("data-equivalent-of=mutations")
        self.assertEqual(table.count("it is not counted as a detection"), 2)

    def test_an_invalid_baseline_shows_no_sensitivity_figure(self) -> None:
        """Requirement 26: even a figure and counts carried by the report are withheld."""
        report = mutation_report(
            detected_records(),
            baseline={"status": "FAIL", "reason": "INVALID_BASELINE"},
            sensitivity={"fraction": "7/9", "decimal": "0.7777"},
            executed_mutations=9,
        )
        page = Page(render(DOCS["pass"], report))
        text = page.text("#mutations")
        self.assertIn(NO_SENSITIVITY_SENTENCE, text)
        self.assertNotIn("7/9", text)
        self.assertNotIn("0.7777", text)
        self.assertIn("although its baseline is invalid", text)

    def test_no_figure_without_a_recorded_baseline_or_an_executed_mutation(self) -> None:
        unrecorded = {"mutations": detected_records(), "sensitivity": {"fraction": "2/3", "decimal": "0.667"}}
        self.assertIn(NO_SENSITIVITY_SENTENCE, render(DOCS["pass"], unrecorded))
        skipped = mutation_report([mutation_record("M15_skipped_required_checker", state="SKIPPED")],
                                  sensitivity={"fraction": "0/0"})
        view = _html._mutation_view(skipped)
        self.assertIsNone(view.sensitivity)
        self.assertNotIn("0/0", render(DOCS["pass"], skipped))

    def test_counts_that_disagree_with_the_records_are_reported(self) -> None:
        report = mutation_report(detected_records(), detected_mutations=3, executed_mutations=3)
        text = Page(render(DOCS["pass"], report)).text("#mutations")
        self.assertIn("inconsistent with its own records", text)
        self.assertIn("detected_mutations 3, but its records give 2", text)

    def test_structured_results_and_fired_detectors_are_readable(self) -> None:
        """The record shape the mutation stage emits: results and fired detectors are objects, not strings."""
        executed = mutation_record("M03_deleted_accepted_row")
        executed.update(
            expected_result={"status": "not PASS", "detector": "check:snapshot_completeness",
                             "rule": "the status is not PASS and check:snapshot_completeness reports FAIL"},
            actual_result={"mode": "verify", "status": "FAIL", "reason": "SOURCE_MISMATCH", "run_id": "run-synthetic"},
            detecting_invariants_fired=[{"detector": "check:snapshot_completeness", "source": "check:snapshot",
                                         "status": "FAIL", "reason": "SOURCE_MISMATCH", "failure_modes": [],
                                         "detail": "synthetic"}],
        )
        skipped = mutation_record("M09_changed_doi", state="NOT_APPLICABLE", detected=None, applicable=False)
        skipped.update(actual_result=None, detecting_invariants_fired=None, blind_spot=None)
        table = Page(render(DOCS["pass"], mutation_report([executed, skipped]))).text("data-equivalent-of=mutations")
        self.assertIn("the status is not PASS and check:snapshot_completeness reports FAIL", table)
        self.assertIn("FAIL (SOURCE_MISMATCH)", table)
        self.assertIn("check:snapshot_completeness FAIL", table)
        self.assertIn("NOT_APPLICABLE", table)

    def test_an_unusable_report_is_said_to_be_unusable(self) -> None:
        self.assertIn("The mutation report is not a JSON object", render(DOCS["pass"], ["not", "a", "report"]))
        self.assertNotIn('id="mutations"', page_source("pass"))


# ---------------------------------------------------------------------------
# Escaping, invisible characters and secrets
# ---------------------------------------------------------------------------


def poisoned(value: str) -> dict[str, Any]:
    """A PASS document with ``value`` written into every text field the page shows."""
    document = doc()
    document["run_id"] = value
    document["status"] = value
    document["manifest"].update(file=value, run_label=value, sha256=value)
    document["evidence_boundary"] = {"integrity": value, "performance": value, "scientific_validity": value}
    document["disclaimer"] = value
    document["tool"] = {"name": value, "version": value}
    document["receipt"]["content_sha256"] = value
    document["ledger_head_sha256"] = value
    for index, (check, spec) in enumerate(zip(document["checks"], document["declared"]["checks"])):
        check_id = f"{value}{index}"
        check.update(check_id=check_id, kind=value, reason=value, diagnostics=[value], failure_modes=[value])
        check["evidence"] = {value: [value]}
        spec.update(id=check_id, kind=value)
    for record in document["accounting"]["inputs"]:
        record.update(id=value, path=value, state=value, sha256=value, diagnostics=[value])
    for item in document["invariants"]:
        item.update(detail=value)
    document["invariants"].append({"name": value, "applicable": True, "holds": False, "detail": value})
    document["findings"] = [{"status": value, "reason": value, "source": value, "failure_modes": [value],
                             "detail": value}]
    document["documents"] = [{"path": value, "roles": [value], "state": value, "sha256": value, "bytes": 1,
                              "diagnostic": value}]
    document["claim_tallies"] = [{"check_id": value, "subject": value, "claimed": 1, "invocations": 0}]
    document["reverification"] = {"ok": False, "problems": [value], "notes": [value],
                                  "receipt": {"signature_state": value}, "ledger": {"observed_head": value},
                                  "invariants": [{"name": value, "holds": False, "detail": value}]}
    document["recorded_status"] = value
    return document


class EscapingTests(unittest.TestCase):
    def assert_inert(self, source: str) -> None:
        page = Page(source)
        self.assertEqual(page.problems, [])
        self.assertFalse({"script", "img"} & {tag for tag, _ in page.elements})
        for tag, attributes in page.elements:
            self.assertFalse([name for name in attributes if name.startswith("on")], tag)
        self.assertNotIn("<script", source)
        self.assertIn("&lt;script&gt;", source)
        self.assertIn("&amp;amp;", source)

    def test_every_document_value_is_escaped(self) -> None:
        self.assert_inert(render(poisoned(HOSTILE)))

    def test_every_mutation_report_value_is_escaped(self) -> None:
        record = mutation_record(HOSTILE, detected=False)
        record.update(description=HOSTILE, expected_detector=HOSTILE, actual_result=HOSTILE,
                      detecting_invariants_fired=[HOSTILE], diagnostics=[HOSTILE])
        report = mutation_report([record], baseline={"status": HOSTILE}, sensitivity={"fraction": HOSTILE})
        self.assert_inert(render(DOCS["pass"], report))

    def test_characters_that_hide_or_reorder_text_are_made_visible(self) -> None:
        document = doc()
        document["manifest"]["run_label"] = "A\u202eB\u200bC\x00D\ud800E\u2066F"
        source = render(document)
        for character in ("\u202e", "\u200b", "\x00", "\ud800", "\u2066"):
            self.assertNotIn(character, source)
        self.assertIn("A\ufffdB\ufffdC\ufffdD\ufffdE\ufffdF", source)
        source.encode("utf-8")  # a lone surrogate would make the page unwritable

    def test_secrets_are_redacted_again_on_output(self) -> None:
        """The page is an output file too (section 15); a mutation report was never redacted upstream."""
        environment_secret = "synthetic-html-secret-4f2a9c71"
        shaped_token = "ghp_" + "Z" * 36
        document = doc()
        document["checks"][0]["diagnostics"] = [f"leaked {environment_secret} and {shaped_token}"]
        report = mutation_report([mutation_record("M01_empty_input")])
        report["mutations"][0]["description"] = f"leaked {environment_secret}"
        with mock.patch.dict(os.environ, {"SCIENCE_GATE_HTML_TEST_TOKEN": environment_secret}):
            source = render(document, report)
        self.assertNotIn(environment_secret, source)
        self.assertNotIn(shaped_token, source)
        self.assertIn("[REDACTED]", source)


# ---------------------------------------------------------------------------
# The PASS contract
# ---------------------------------------------------------------------------


class PassContractTests(unittest.TestCase):
    def assert_unsupported(self, document: dict[str, Any], gap: str) -> None:
        self.assertIn(gap, gaps(document))
        source = render(document)
        self.assertIn('id="contradiction-heading"', source)
        self.assertIn('class="verdict t-critical"', source)
        self.assertIn("<strong>unsupported</strong>", source)

    def test_a_consistent_pass_is_shown_as_pass(self) -> None:
        self.assertEqual(gaps(doc()), [])
        source = page_source("pass")
        self.assertNotIn('id="contradiction-heading"', source)
        self.assertIn('class="verdict t-good"', source)

    def test_a_pass_with_no_examined_rows_is_unsupported(self) -> None:
        """Requirement 3 as the page shows it."""
        document = doc()
        document["rows_examined"] = 0
        self.assert_unsupported(document, "rows_examined is 0; a PASS needs at least 1")

    def test_a_pass_with_a_missing_required_input_is_unsupported(self) -> None:
        document = doc()
        document["accounting"]["inputs"][0]["state"] = "MISSING"
        self.assert_unsupported(document, "required input measurements is MISSING, not PARSED")

    def test_a_pass_with_unknown_counters_is_unsupported(self) -> None:
        document = doc()
        document["checks_executed"] = None
        self.assert_unsupported(document, "checks_executed is unknown but checks_expected is 6")

    def test_a_pass_with_a_violated_or_unrecorded_invariant_is_unsupported(self) -> None:
        document = doc()
        document["invariants"] = [item for item in document["invariants"] if item["name"] != "ledger_chain_intact"]
        self.assert_unsupported(document, "invariant ledger_chain_intact is NOT_RECORDED")

    def test_other_statuses_are_never_called_contradictions(self) -> None:
        for name in ("empty", "missing", "hash", "error"):
            self.assertEqual(gaps(doc(name)), [], name)


# ---------------------------------------------------------------------------
# Determinism and robustness
# ---------------------------------------------------------------------------


def _reordered(value: Any) -> Any:
    """The same JSON value with every object's keys in reverse order."""
    if isinstance(value, dict):
        return {key: _reordered(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [_reordered(item) for item in value]
    return value


_RENDER_SCRIPT = (
    "import json, sys\n"
    "from science_gate._html import render\n"
    "with open(sys.argv[1], encoding='utf-8') as handle:\n"
    "    case = json.load(handle)\n"
    "sys.stdout.buffer.write(render(case['run'], case['mutation']).encode('utf-8'))\n"
)


class DeterminismTests(unittest.TestCase):
    def test_the_same_document_renders_to_the_same_bytes(self) -> None:
        report = mutation_report(detected_records())
        first = render(DOCS["pass"], report)
        self.assertEqual(render(copy.deepcopy(DOCS["pass"]), copy.deepcopy(report)), first)
        self.assertEqual(render(_reordered(DOCS["pass"]), _reordered(report)), first)
        shuffled = mutation_report(list(reversed(detected_records())))
        self.assertEqual(render(DOCS["pass"], shuffled), first)

    def test_output_does_not_depend_on_the_hash_seed(self) -> None:
        """Requirement 13 for the page: two interpreters with different hash seeds write identical bytes."""
        report = mutation_report(detected_records())
        case = _WORKSPACE[0] / "determinism-case.json"
        case.write_text(json.dumps({"run": DOCS["pass"], "mutation": report}), encoding="utf-8")
        outputs = []
        for seed in ("0", "4242"):
            environment = {
                **os.environ,
                "PYTHONHASHSEED": seed,
                "PYTHONPATH": str(SRC_DIR),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            completed = subprocess.run(
                [sys.executable, "-c", _RENDER_SCRIPT, str(case)], env=environment, capture_output=True, timeout=120
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
            outputs.append(completed.stdout)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[0], render(DOCS["pass"], report).encode("utf-8"))


class RobustnessTests(unittest.TestCase):
    def assert_renders(self, value: Any, mutation: Any = None) -> str:
        source = render(value, mutation)
        self.assertIsInstance(source, str)
        self.assertEqual(Page(source).problems, [])
        return source

    def test_any_value_renders(self) -> None:
        for value in (None, [], "run", 7, True, {}, {"status": ["PASS"]}, {"checks": "x"}):
            source = self.assert_renders(value)
            self.assertIn("Unidentified run", source)
        self.assertIn("The run document is not a JSON object", render(None))

    def test_every_top_level_field_can_hold_the_wrong_type(self) -> None:
        for key in sorted(DOCS["pass"]):
            document = doc()
            document[key] = JUNK
            self.assert_renders(document)
        for bad in (None, "text", 0):
            self.assert_renders({key: bad for key in DOCS["pass"]})

    def test_every_nested_field_can_hold_the_wrong_type(self) -> None:
        document = doc()
        containers = [
            document["accounting"]["inputs"],
            document["checks"],
            document["invariants"],
            document["documents"],
            document["declared"]["checks"],
            document["declared"]["inputs"],
        ]
        for container in containers:
            for item in container:
                for key in list(item):
                    item[key] = JUNK
        for counter in document["accounting"]["counters"].values():
            counter["value"] = "7"
        document["accounting"]["closure"] = {"holds": "yes", "source": JUNK}
        document["findings"] = [JUNK, {"status": JUNK}]
        self.assert_renders(document)
        for key in ("checks", "invariants", "findings", "documents"):
            wrong = doc()
            wrong[key] = ["x", 1, None]
            self.assert_renders(wrong)

    def test_a_malformed_mutation_report_still_renders(self) -> None:
        for report in ({}, {"mutations": JUNK}, {"mutations": [{"mutation_id": JUNK, "execution_state": JUNK}]},
                       {"baseline": JUNK, "counts": JUNK, "sensitivity": JUNK}):
            self.assert_renders(DOCS["pass"], report)

    def test_evidence_that_cannot_be_hashed_is_reported_not_raised(self) -> None:
        document = doc()
        document["checks"][0]["evidence"] = {"ratio": 0.5}
        self.assertIn("1 field(s), not canonical", render(document))

    def test_deeply_nested_values_do_not_raise(self) -> None:
        nested: Any = []
        for _ in range(5000):
            nested = [nested]
        document = doc()
        document["run_id"] = nested
        self.assert_renders(document)


# ---------------------------------------------------------------------------
# Integration with the run directory
# ---------------------------------------------------------------------------


class RunDirectoryIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.out = Path(tempfile.mkdtemp(prefix="science-gate-html-run-")).resolve()
        self.addCleanup(shutil.rmtree, self.out, ignore_errors=True)

    def test_verify_writes_the_page_rendered_from_run_json_alone(self) -> None:
        written = write_run(RUNS["pass"], self.out / "run", environ={})
        self.assertIn(REPORT_HTML, [path.name for path in written.paths])
        recorded = json.loads((self.out / "run" / RUN_JSON).read_text(encoding="utf-8"))
        self.assertEqual((self.out / "run" / REPORT_HTML).read_text(encoding="utf-8"), render(recorded))
        self.assertNotIn("report.html was not written", (self.out / "run" / REPORT_MD).read_text(encoding="utf-8"))

    def test_a_tampered_run_is_rerendered_as_error(self) -> None:
        run_dir = self.out / "run"
        write_run(RUNS["pass"], run_dir, environ={})
        recorded = json.loads((run_dir / RUN_JSON).read_text(encoding="utf-8"))
        recorded["rows_examined"] = 999
        (run_dir / RUN_JSON).write_text(json.dumps(recorded), encoding="utf-8")
        report_run_dir(run_dir, environ={})
        page = Page((run_dir / REPORT_HTML).read_text(encoding="utf-8"))
        self.assertIn('<span class="verdict-word">ERROR</span>', page.source)
        self.assertIn("Re-verification failed", page.source)
        self.assertIn("the recorded status PASS is not trusted", page.source)
        self.assertIn("Recorded reasons", page.source)
        self.assertIn("RUN_RECEIPT_MISMATCH", page.text("#reverification"))
        self.assertEqual(states(planes(recorded | {"reverification": {"ok": False}})[0])["Re-verification"], "BROKEN")

    def test_a_reverified_run_says_so(self) -> None:
        run_dir = self.out / "run"
        write_run(RUNS["pass"], run_dir, environ={})
        report_run_dir(run_dir, environ={})
        page = Page((run_dir / REPORT_HTML).read_text(encoding="utf-8"))
        self.assertIn("PASSED", page.text("#reverification"))
        self.assertIn("LIT Re-verification receipt, ledger chain and run.json re-verified from disk",
                      page.text("data-equivalent-of=hologram"))
        self.assertNotIn("Re-verification failed", page.source)


if __name__ == "__main__":
    unittest.main()
