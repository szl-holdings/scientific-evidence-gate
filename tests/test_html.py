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
import hashlib
import html
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
from science_gate.invariants import INVARIANT_NAMES, PLANNED_CONTROLS
from science_gate.mutations import OPERATOR_IDS, mutate
from science_gate.receipts import build_run_receipt
from science_gate.reports import REPORT_HTML, REPORT_MD, RUN_JSON, report_run_dir, run_document, write_run
from science_gate.verifier import VerificationRun, verify

EMPTY_MANIFEST = REPO_ROOT / "fixtures" / "core" / "empty" / "manifest.json"
#: Synthetic fixtures whose runs carry the frontier evidence: a claim join, a resolving resolver canary, a GRIM test.
CLAIM_JOIN_MANIFEST = REPO_ROOT / "fixtures" / "assertions" / "five-cases" / "manifest.json"
CANARY_MANIFEST = REPO_ROOT / "fixtures" / "citations" / "canary-resolved" / "manifest.json"
GRIM_MANIFEST = REPO_ROOT / "fixtures" / "numeric" / "grim-inconsistent" / "manifest.json"
VISUALS = {"hologram", "accounting", "lattice", "controls", "discrimination", "plan", "invariants", "ledger"}

#: Markup that would run code, load a resource or break out of an attribute if it were not escaped.
HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(1)>"\' onmouseover="alert(1)" &amp; </svg></table>'
#: A wrong-typed value that contains every JSON kind the renderer might trip over.
JUNK = [None, 1, "x", {"k": []}, [2], True]


# ---------------------------------------------------------------------------
# Synthetic runs, built once per module
# ---------------------------------------------------------------------------

RUNS: dict[str, VerificationRun] = {}
DOCS: dict[str, dict[str, Any]] = {}
#: Mutation reports exactly as ``mutate`` writes them: one with a valid baseline, one without.
REPORTS: dict[str, dict[str, Any]] = {}
_PAGES: dict[str, str] = {}
_WORKSPACE: list[Path] = []


def _document(run: VerificationRun) -> dict[str, Any]:
    """The run.json document exactly as ``verify`` would write it, unsigned."""
    seal = run.ledger.seal()
    receipt = build_run_receipt(
        run.result, ledger_head_sha256=seal["ledger_head_sha256"], ledger_length=seal["ledger_length"], environ={}
    )
    return run_document(run, receipt)


#: The only variables this module's code sees, besides the fixed clock. Redaction scans the whole
#: environment for every string it cleans, and a page cleans hundreds, so a machine's hundred-odd variables
#: would dominate every render. A pinned environment also makes the pages independent of whatever
#: secret-named variables the machine happens to hold, and leaves out the signing-key variable, so every
#: receipt here is UNSIGNED. These few are what the interpreter and the temporary-directory lookup need.
_KEPT_VARIABLES = frozenset({"PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "PYTHONHASHSEED"})


def setUpModule() -> None:
    kept = {name: value for name, value in os.environ.items() if name.upper() in _KEPT_VARIABLES}
    environment = mock.patch.dict(os.environ, kept | {"SCIENCE_GATE_FIXED_TIME": FIXED_TIME}, clear=True)
    environment.start()
    unittest.addModuleCleanup(environment.stop)
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

    # An accepted row is deleted and the digest re-declared, so only the checks themselves can catch it.
    deleted = project("deleted")
    data = deleted / "data" / "measurements.csv"
    data.write_bytes(b"".join(line for line in data.read_bytes().splitlines(True) if not line.startswith(b"SYN-0003")))
    manifest = json.loads((deleted / "manifest.json").read_text(encoding="utf-8"))
    manifest["inputs"][0]["sha256"] = hashlib.sha256(data.read_bytes()).hexdigest()
    (deleted / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    RUNS["deleted"] = verify(deleted / "manifest.json")

    broken = project("error")
    (broken / "manifest.json").write_text('{"schema": "not-a-science-gate-manifest/v0"}', encoding="utf-8")
    RUNS["error"] = verify(broken / "manifest.json")

    RUNS["claim_join"] = verify(CLAIM_JOIN_MANIFEST)
    RUNS["canary"] = verify(CANARY_MANIFEST)
    RUNS["grim"] = verify(GRIM_MANIFEST)

    DOCS.update({name: _document(run) for name, run in RUNS.items()})

    REPORTS["valid"] = mutate(project("mutate") / "manifest.json").to_dict()
    unaccepting = project("mutate-invalid")
    (unaccepting / "data" / "measurements.csv").unlink()
    REPORTS["invalid"] = mutate(unaccepting / "manifest.json").to_dict()


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
    Pieces of text join with a space, except that punctuation opening a piece
    attaches to the word before it, as a reader sees ``<code>inv-1</code>, derived``.
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
        joined = "".join(piece if piece[:1] in ",;:.)" else " " + piece for piece in self.captured.get(key, []))
        return " ".join(joined.split())

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
# The masthead: what the status is, and why
# ---------------------------------------------------------------------------


def finding(status: str, reason: str, detail: str) -> dict[str, Any]:
    return {"status": status, "reason": reason, "failure_modes": [], "source": "input:synthetic", "detail": detail}


class MastheadTests(unittest.TestCase):
    def verdict(self, source: str) -> str:
        return Page(source).text("#status")

    def test_an_error_says_why_on_the_first_screen(self) -> None:
        verdict = self.verdict(page_source("error"))
        self.assertIn("Why ERROR", verdict)
        self.assertIn("SCHEMA_MISMATCH at /schema", verdict)

    def test_a_failure_names_only_the_findings_that_decided_it(self) -> None:
        document = doc("hash")
        document["findings"] = [
            finding("ABSTAIN", "INSUFFICIENT_EVIDENCE", "synthetic abstention, not decisive"),
            finding("FAIL", "SOURCE_MISMATCH", "synthetic digest disagreement"),
        ]
        verdict = self.verdict(render(document))
        self.assertIn("Why FAIL", verdict)
        self.assertIn("synthetic digest disagreement", verdict)
        self.assertNotIn("synthetic abstention", verdict)
        self.assertIn("HASH_MISMATCH", self.verdict(page_source("hash")))

    def test_many_grounds_are_capped_with_a_link_to_all_of_them(self) -> None:
        document = doc("hash")
        document["findings"] = [finding("FAIL", "SOURCE_MISMATCH", f"synthetic ground {n}") for n in range(5)]
        source = render(document)
        verdict = self.verdict(source)
        self.assertIn("synthetic ground 2", verdict)
        self.assertNotIn("synthetic ground 3", verdict)
        self.assertIn("2 more under Findings", verdict)
        self.assertIn('<a href="#findings">', source)
        self.assertIn("synthetic ground 4", Page(source).text("#findings"))

    def test_a_status_with_no_recorded_grounds_is_called_unexplained(self) -> None:
        document = doc("hash")
        document["findings"] = []
        self.assertIn("nothing on record explains it", self.verdict(render(document)))

    def test_a_pass_and_a_rejected_run_carry_no_why(self) -> None:
        self.assertNotIn("Why", self.verdict(page_source("pass")))
        rejected = doc("hash") | {"status": "ERROR", "recorded_status": "FAIL", "reverification": {"ok": False}}
        verdict = self.verdict(render(rejected))
        self.assertNotIn("Why", verdict)
        self.assertIn("the recorded status FAIL is not trusted", verdict)

    def test_reasons_and_failure_modes_are_labelled_rows(self) -> None:
        verdict = self.verdict(page_source("hash"))
        self.assertRegex(verdict, r"Reasons( [A-Z_]+)+ Failure modes( [A-Z_]+)+")

    def test_manifest_issues_are_listed_with_their_location(self) -> None:
        table = Page(page_source("error")).text("#findings")
        self.assertIn("Manifest issues", table)
        self.assertIn("SCHEMA_MISMATCH /schema", table)
        document = doc("error")
        document["manifest"]["issues"] = [{"code": "RUN_UNREADABLE", "pointer": "", "message": "synthetic"}]
        self.assertIn("RUN_UNREADABLE / synthetic", Page(render(document)).text("#findings"))
        self.assertNotIn("Manifest issues", page_source("pass"))


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
                "Harness pins": "LIT",
                "Plan committed": "LIT",
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
        forged = doc()
        forged["receipt"]["signature_state"] = "SIGNED_HMAC_SHA256"
        forged["reverification"] = {"ok": False, "receipt": {"signature_verified": False}, "ledger": {"intact": True}}
        self.assertEqual(states(planes(forged)[0])["Signature"], "BROKEN")

    def test_a_deleted_row_breaks_the_evaluation(self) -> None:
        """Requirement 9 as the page shows it: the checks catch the deletion, and the Performance plane reads broken."""
        self.assertEqual(DOCS["deleted"]["status"], "FAIL")
        performance = states(planes(doc("deleted"))[1])
        for name in ("Required checks passed", "Row closures", "Evaluation invariants"):
            self.assertEqual(performance[name], "BROKEN", name)
        self.assertEqual(states(planes(doc("deleted"))[0])["Declared digests"], "LIT")
        terminal = {row.check_id: row.terminal.label for row in _html._lattice_rows(doc("deleted"))}
        self.assertEqual(terminal["snapshot"], "FAIL")
        page = Page(page_source("deleted"))
        self.assertIn("Why FAIL", page.text("#status"))
        self.assertIn("OMITTED_POPULATION", page.text("data-equivalent-of=lattice"))
        self.assertIn('class="plane-edge broken"', page.source)

    def test_a_signature_not_checked_never_reads_as_verified(self) -> None:
        """Re-verification records None both for an unsigned receipt and for a signature checked without its key."""
        words = {
            (True, "SIGNED_HMAC_SHA256"): "signature verified",
            (False, "SIGNED_HMAC_SHA256"): "signature did NOT verify",
            (None, "UNSIGNED"): "no signature to verify",
            (None, "SIGNED_HMAC_SHA256"): "signature not checked",
            (None, None): "signature not checked",
        }
        for (verified, state), expected in words.items():
            receipt = {"signature_verified": verified, "signature_state": state}
            self.assertEqual(_html._signature_check(receipt), expected, receipt)


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
        document = doc()
        document["accounting"]["closure"] = {"source": "INDEPENDENT", "holds": False, "expected": 2, "accounted": 1}
        self.assertIn("Closure BROKEN \u00b7 1 accounted of 2 expected", render(document))
        self.assertEqual(states(planes(document)[1])["Input closure"], "BROKEN")

    def test_closures_without_an_independent_count_leave_the_row_facet_partial(self) -> None:
        document = doc()
        extra = copy.deepcopy(document["accounting"]["inputs"][0])
        extra.update(id="synthetic-extra", closure={"source": "OBSERVED", "holds": None, "expected": None,
                                                    "accounted": 6})
        document["accounting"]["inputs"].append(extra)
        (facet,) = [item for item in planes(document)[1].facets if item.name == "Row closures"]
        self.assertEqual((facet.state, facet.detail),
                         ("PARTIAL", "1 of 2 input(s) close; the rest have no INDEPENDENT expected_rows"))

    def test_partly_unknown_dispositions_and_tiny_counts_stay_visible(self) -> None:
        """One failed file among a thousand is still drawn, and an unknown disposition is never added as zero."""
        document = doc()
        counters = document["accounting"]["counters"]
        for name in ("expected", "discovered", "opened", "parsed", "examined"):
            counters[name]["value"] = 1000
        counters["admitted"]["value"], counters["failed"]["value"], counters["deferred"]["value"] = 999, 1, None
        source = render(document)
        funnel = svg_of(source, "accounting")
        self.assertIn("1000 + unknown (deferred)", funnel)
        self.assertIn("<title>failed: 1</title>", funnel)
        self.assertIn("<td>deferred</td><td>unknown</td>", source)

    def test_missing_required_input_stays_visible(self) -> None:
        """Requirement 6 as the page shows it: the missing file keeps its row and its state."""
        page = Page(page_source("missing"))
        self.assertIn("measurements", page.text("#inputs"))
        self.assertIn("MISSING", page.text("#inputs"))
        self.assertIn("0 of 6 \u00b7 MISSING", svg_of(page.source, "accounting"))
        facet = [item for item in planes(doc("missing"))[1].facets if item.name == "Required inputs parsed"][0]
        self.assertEqual((facet.state, facet.detail), ("DARK", "0 of 1 required input(s) PARSED; measurements MISSING"))


class InputsTableTests(unittest.TestCase):
    def test_computed_and_declared_digests_are_read_together(self) -> None:
        """Requirement 23 as the page shows it: a changed input is read against its declared digest."""
        record = DOCS["hash"]["accounting"]["inputs"][0]
        text = Page(page_source("hash")).text("#inputs")
        self.assertIn(f"{record['sha256']} declared {record['declared_sha256']} \u00b7 mismatch", text)
        self.assertIn("\u00b7 <strong>mismatch</strong>", page_source("hash"))
        unchanged = DOCS["pass"]["accounting"]["inputs"][0]
        self.assertIn(f"{unchanged['sha256']} declared {unchanged['sha256']} \u00b7 match",
                      Page(page_source("pass")).text("#inputs"))
        undeclared = doc()
        undeclared["accounting"]["inputs"][0]["declared_sha256"] = None
        self.assertIn(f"{unchanged['sha256']} no digest declared", Page(render(undeclared)).text("#inputs"))

    def test_a_declared_input_with_no_accounting_record_keeps_a_row(self) -> None:
        document = doc()
        document["accounting"]["inputs"] = []
        text = Page(render(document)).text("#inputs")
        declared = DOCS["pass"]["declared"]["inputs"][0]
        self.assertIn("NO RECORD", text)
        self.assertIn(f"none declared {declared['sha256']} \u00b7 not compared", text)
        self.assertIn("declared in the manifest but absent from the accounting", text)

    def test_paths_wrap_only_at_separators_and_empty_diagnostics_say_none(self) -> None:
        source = page_source("pass")
        self.assertIn('<code class="brk">data/<wbr>measurements.csv</code>', source)
        start = source.index('<div class="table-wrap input-table"')
        row = source[start : source.index("</tr>", source.index("<tbody>", start))]
        self.assertTrue(row.endswith('<td><span class="muted">none</span></td>'), row[-120:])
        self.assertEqual(_html._path("a\\b_c-d&e"), '<code class="brk">a\\<wbr>b_<wbr>c-<wbr>d&amp;e</code>')


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

    def test_every_fact_of_a_check_sits_in_its_row(self) -> None:
        """Seven columns, with each secondary fact under the one it qualifies, so none needs a sideways scroll."""
        source = page_source("hash")
        start = source.index('<div class="table-wrap check-table"')
        table = source[start : source.index("</table>", start)]
        self.assertEqual(table.count('<th scope="col">'), 7)
        check = DOCS["hash"]["checks"][0]
        row = table[table.index(f"<code>{check['check_id']}</code>") :]
        row = row[: row.index("</tr>")]
        self.assertEqual(row.count("<td>"), 6)  # the row's first cell opened before the slice
        for fact in (check["kind"], check["reason"], check["invocation_id"], *check["failure_modes"],
                     *check["diagnostics"], "field(s), sha256"):
            self.assertIn(html.escape(fact), row)

    def test_partial_execution_cannot_look_complete(self) -> None:
        """Requirement 7 as the page shows it."""
        source = page_source("empty")
        self.assertIn('<div class="stat-value">0 / 3</div>', source)
        self.assertIn(">0 checked<", svg_of(source, "lattice"))
        self.assertEqual(set(self.cells(doc("empty")).values()), {("REQUIRED", "NOT_APPLICABLE", "ABSTAIN")})
        partial = doc()
        partial["checks_executed"] = 5
        self.assertIn("checks_executed is 5 but checks_expected is 6", gaps(partial))
        excessive = doc()
        excessive["checks_executed"] = 7
        self.assertEqual(states(planes(excessive)[1])["Required checks executed"], "BROKEN")
        self.assertIn("checks_executed is 7 but checks_expected is 6", gaps(excessive))

    def test_an_optional_check_that_did_not_run_is_shown_but_does_not_decide(self) -> None:
        """An optional check stays visible as OPTIONAL and SKIPPED; like ``decide``, the page does not hold it
        against a PASS."""
        document = doc()
        (spec,) = [item for item in document["declared"]["checks"] if item["id"] == "rows"]
        (result,) = [item for item in document["checks"] if item["check_id"] == "rows"]
        spec["required"] = False
        result.update(required=False, execution_state="SKIPPED", verdict="ABSTAIN", reason="INSUFFICIENT_EVIDENCE")
        self.assertEqual(self.cells(document)["rows"], ("OPTIONAL", "SKIPPED", "ABSTAIN"))
        self.assertEqual(gaps(document), [])
        self.assertIn(">5 required + 1<", svg_of(render(document), "lattice"))


# ---------------------------------------------------------------------------
# Invariant ring
# ---------------------------------------------------------------------------


class InvariantRingTests(unittest.TestCase):
    def test_one_segment_per_invariant(self) -> None:
        ring = svg_of(page_source("pass"), "invariants")
        total = len(INVARIANT_NAMES)
        self.assertEqual(ring.count("<title>"), total)  # one tooltip per segment; the figure's own title has an id
        self.assertIn(f">{total} of {total}<", ring)

    def test_the_list_shows_the_numbers_the_ring_refers_to(self) -> None:
        """A grid list item loses its marker, so the numbers are written out and must match the ring's labels."""
        source = page_source("pass")
        start = source.index('<ol class="invariant-list"')
        listing = source[start : source.index("</ol>", start)]
        written = re.findall(r'<li value="(\d+)"><span class="inv-num" aria-hidden="true">(\d+)</span>', listing)
        self.assertEqual(written, [(str(n), str(n)) for n in range(1, len(INVARIANT_NAMES) + 1)])
        labels = re.findall(r'text-anchor="middle">(\d+)</text>', svg_of(source, "invariants"))
        self.assertEqual(sorted(labels, key=int), [str(n) for n in range(1, len(INVARIANT_NAMES) + 1)])
        listed = Page(source).text("data-equivalent-of=invariants")
        # Rows follow the document's order, so the number is the invariant's position in run.json.
        number = [item["name"] for item in DOCS["pass"]["invariants"]].index("checked_claims_le_invocations") + 1
        self.assertIn(f"{number} {_html._GLYPH_TEXT['check']} HOLDS checked_claims_le_invocations", listed)

    def test_contract_invariants_missing_from_the_document_are_listed(self) -> None:
        document = doc()
        document["invariants"] = document["invariants"][:3]
        rows = _html._invariant_rows(document)
        missing = len(INVARIANT_NAMES) - 3
        self.assertEqual(len(rows), len(INVARIANT_NAMES))
        self.assertEqual(sum(1 for row in rows if row.state == "NOT_RECORDED"), missing)
        page = Page(render(document))
        self.assertEqual(page.text("data-equivalent-of=invariants").count("NOT_RECORDED"), missing)
        self.assertIn(f"{missing} not recorded", svg_of(page.source, "invariants"))

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
        # Controls (falsifiers, the canary pair, the comparator) are invocations with no check result to place.
        started = {
            entry["invocation_id"]: entry["seq"]
            for entry in entries
            if entry["result"] == "STARTED" and not entry["check_id"].startswith("control:")
        }
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
        self.assertIn("SKIPPED OR N/A \u00b7 3", svg_of(source, "mutations"))
        self.assertIn("NEVER EXECUTED \u00b7 0", svg_of(source, "mutations"))
        table = Page(source).text("data-equivalent-of=mutations")
        self.assertEqual(table.count("it is not counted as a detection"), 2)

    def test_report_v2_statuses_that_never_executed_are_neither_skipped_nor_detected(self) -> None:
        """A v2 record (17.12) that was never executed is its own group: not SKIPPED, never a detection."""
        records = detected_records()
        for mutation_id, status in (
            ("M07_changed_source_hash", "NOT_ACTIVATED"),
            ("M11_changed_numeric_formatting", "CANONICALLY_EQUIVALENT"),
            ("M12_timezone_shift", "NOOP_MUTATION"),
            ("M14_pass_summary_without_evidence", "DUPLICATE_MUTANT"),
        ):
            records.append(dict(mutation_record(mutation_id, state="SKIPPED", detected=None), status=status))
        records.append(dict(mutation_record("M04_duplicate_row", state="SKIPPED", detected=None), status="SKIPPED"))
        crashed = dict(mutation_record("M10_changed_numeric_value", detected=False), status="VERIFIER_ERROR")
        crashed["blind_spot"] = False
        records.append(crashed)
        report = mutation_report(
            records, executed_mutations=4, detected_mutations=2, escaped_mutations=2, skipped_mutations=1
        )
        view = _html._mutation_view(report)
        self.assertEqual(len(view.group("NOT_EXECUTED")), 4)
        self.assertEqual(view.tallies["skipped_mutations"], 1, "only status SKIPPED counts as skipped")
        self.assertEqual(view.tallies["detected_mutations"], 2)
        self.assertEqual(view.discrepancies, ())
        (error,) = [item for item in view.mutations if item.short == "M10"]
        self.assertIn("VERIFIER_ERROR", error.note)
        source = render(DOCS["pass"], report)
        stars = svg_of(source, "mutations")
        self.assertIn("NEVER EXECUTED \u00b7 4", stars)
        self.assertIn("SKIPPED OR N/A \u00b7 1", stars)
        # The cluster names the statuses it holds, so a no-op is never read as a skip.
        self.assertIn("CANONICALLY_EQUIVALENT 1, DUPLICATE_M", stars)

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
        source = render(DOCS["pass"], mutation_report([executed, skipped]))
        table = Page(source).text("data-equivalent-of=mutations")
        self.assertIn("the status is not PASS and check:snapshot_completeness reports FAIL", table)
        self.assertIn("FAIL (SOURCE_MISMATCH)", table)
        self.assertIn("check:snapshot_completeness FAIL", table)
        self.assertIn("NOT_APPLICABLE", table)
        # The recorded execution state is shown under the group only when it adds something.
        self.assertIn('DETECTED</span><div class="cell-sub">CHECKED</div>', source)
        self.assertNotIn('NOT_APPLICABLE</span><div class="cell-sub">NOT_APPLICABLE</div>', source)

    def test_an_unusable_report_is_said_to_be_unusable(self) -> None:
        self.assertIn("The mutation report is not a JSON object", render(DOCS["pass"], ["not", "a", "report"]))
        self.assertNotIn('id="mutations"', page_source("pass"))


def ruled_record(mutation_id: str, fired: list[Any] | None, *, actual: str = "FAIL",
                 detected: bool | None = True) -> dict[str, Any]:
    """A record in the shape ``mutate`` writes, whose expected detector is stated in full."""
    record = mutation_record(mutation_id, detected=detected)
    record.update(
        expected_detector="check:snapshot_completeness",
        expected_result={"status": "not PASS", "detector": "check:snapshot_completeness",
                         "detector_statuses": ["FAIL"], "detector_signals": ["OMITTED_POPULATION"],
                         "rule": "the status is not PASS and check:snapshot_completeness reports FAIL with "
                                 "OMITTED_POPULATION"},
        actual_result={"mode": "verify", "status": actual, "reason": "SOURCE_MISMATCH", "run_id": "run-synthetic"},
        detecting_invariants_fired=fired,
    )
    return record


def fired(detector: str, status: str, reason: str = "SOURCE_MISMATCH", modes: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"detector": detector, "source": "check:snapshot", "status": status, "reason": reason,
            "failure_modes": list(modes), "detail": "synthetic"}


EXPECTED_FIRE = fired("check:snapshot_completeness", "FAIL", modes=("OMITTED_POPULATION",))


class MutationEvidenceTests(unittest.TestCase):
    """The page re-reads each mutation record's own evidence rather than trusting its ``detected`` flag."""

    def test_a_real_report_renders_without_a_contradiction(self) -> None:
        report = REPORTS["valid"]
        view = _html._mutation_view(report)
        self.assertEqual(view.discrepancies, ())
        self.assertEqual({key: view.tallies[key] for key in _html._MUTATION_COUNT_KEYS},
                         {key: report[key] for key in _html._MUTATION_COUNT_KEYS})
        self.assertEqual(view.sensitivity[0], report["sensitivity"]["fraction"])
        for item in view.mutations:
            if item.group == "DETECTED":
                self.assertEqual(item.firing, "FIRED", item.mutation_id)
            if item.group == "NOT_APPLICABLE":
                self.assertEqual(item.firing, "NOT EXECUTED", item.mutation_id)
        text = Page(render(DOCS["pass"], report)).text("#mutations")
        selected = f"{len(OPERATOR_IDS)} of {len(OPERATOR_IDS)} operators selected"
        for expected in (report["report_id"], report["message"], selected, "Applicable",
                         "Forced detection (M00)", "detected by invariant:ledger_chain_intact", "Conservation",
                         report["sensitivity"]["decimal_rounding"], "What this mutation report does not prove",
                         report["not_proven"][0]):
            self.assertIn(expected, text)
        self.assertNotIn("inconsistent with its own records", text)

    def test_harness_controls_are_shown_as_recorded_and_never_assumed(self) -> None:
        """M00 and the conservation identities (17.12): shown as the report states them, absent as not recorded."""
        report = copy.deepcopy(REPORTS["valid"])
        self.assertEqual(_html._harness_controls(report), ("detected by invariant:ledger_chain_intact", "holds"))
        report["forced_detection"]["detected"] = False
        report["conservation"]["holds"] = False
        forced, conservation = _html._harness_controls(report)
        self.assertTrue(forced.startswith("NOT detected"), forced)
        self.assertEqual(conservation, "does NOT hold")
        for key in ("forced_detection", "conservation"):
            del report[key]
        self.assertEqual(_html._harness_controls(report), ("not recorded", "not recorded"))

    def test_a_real_invalid_baseline_report_shows_no_figure_and_no_counts(self) -> None:
        """Requirement 26 with the report ``mutate`` actually writes: no counts, no records, no figure."""
        report = REPORTS["invalid"]
        self.assertNotIn("sensitivity", report)
        source = render(DOCS["pass"], report)
        text = Page(source).text("#mutations")
        self.assertIn(NO_SENSITIVITY_SENTENCE, text)
        self.assertIn("INVALID_BASELINE", text)
        self.assertNotIn('class="count-strip"', source)
        self.assertNotIn('data-visual="mutations"', source)
        self.assertNotIn("Sensitivity", text)
        for diagnostic in report["baseline"]["diagnostics"]:
            self.assertIn(" ".join(diagnostic.split()), text)

    def test_the_expected_detector_rule_is_matched_in_full(self) -> None:
        rule = _html._detector_rule(ruled_record("M03_deleted_accepted_row", []))
        self.assertTrue(rule.matches(EXPECTED_FIRE))
        self.assertFalse(rule.matches(fired("check:snapshot_completeness", "ABSTAIN", modes=("OMITTED_POPULATION",))))
        self.assertFalse(rule.matches(fired("check:snapshot_completeness", "FAIL")))  # no stated signal raised
        self.assertFalse(rule.matches(fired("check:row_count", "FAIL", modes=("OMITTED_POPULATION",))))
        self.assertTrue(rule.matches(fired("check:snapshot_completeness", "FAIL", reason="OMITTED_POPULATION")))
        self.assertFalse(_html._DetectorRule(None, (), ()).matches(EXPECTED_FIRE))

    def test_a_detection_its_own_evidence_contradicts_is_unresolved(self) -> None:
        """A detected flag is not enough: the actual status and the expected detector must agree with it."""
        records = [
            ruled_record("M01_supported", [fired("check:row_count", "FAIL"), EXPECTED_FIRE]),
            ruled_record("M02_actual_pass", [EXPECTED_FIRE], actual="PASS"),
            ruled_record("M03_wrong_detector", [fired("check:row_count", "FAIL")]),
            ruled_record("M04_nothing_recorded", None),
        ]
        view = _html._mutation_view(mutation_report(records, status="PASS", detected_mutations=4))
        groups = {item.short: (item.group, item.firing) for item in view.mutations}
        self.assertEqual(groups, {"M01": ("DETECTED", "FIRED"), "M02": ("UNRESOLVED", "FIRED"),
                                  "M03": ("UNRESOLVED", "NOT FIRED"), "M04": ("UNRESOLVED", "NOT RECORDED")})
        self.assertEqual(view.tallies["detected_mutations"], 1)
        self.assertIn("the report states detected_mutations 4, but its records give 1", view.discrepancies)
        self.assertIn("the report states PASS, but its records include 0 blind spot(s) and 3 unresolved mutation(s)",
                      view.discrepancies)
        table = Page(render(DOCS["pass"], mutation_report(records))).text("data-equivalent-of=mutations")
        self.assertEqual(table.count("it is not counted as a detection"), 3)
        self.assertIn("check:snapshot_completeness FAIL expected", table)
        self.assertIn("1 finding(s), none from the expected detector", table)

    def test_a_blind_spot_is_never_upgraded(self) -> None:
        record = ruled_record("M20_metadata_change_under_unchanged_pass_summary", [EXPECTED_FIRE], detected=False)
        (item,) = _html._mutation_view(mutation_report([record])).mutations
        self.assertEqual((item.group, item.firing), ("BLIND_SPOT", "FIRED"))
        self.assertIn("it stays a blind spot", item.note)

    def test_a_blind_spot_names_where_the_defect_stopped_mattering(self) -> None:
        """The v2 PIE stage (17.12) is shown as recorded; a record without one shows no stage."""
        record = mutation_record("M05_duplicate_reviewer_verdict", detected=False)
        record["pie_stage"] = "PROPAGATED_NOT_CHECKED"
        (item,) = _html._mutation_view(mutation_report([record])).mutations
        self.assertEqual(item.group, "BLIND_SPOT")
        self.assertIn("stopped mattering at PROPAGATED_NOT_CHECKED", item.note)
        del record["pie_stage"]
        (item,) = _html._mutation_view(mutation_report([record])).mutations
        self.assertNotIn("stopped mattering", item.note or "")

    def test_an_executed_mutation_without_a_detection_result_is_unresolved(self) -> None:
        """Neither a detection nor a blind spot can be assumed when the record does not say which it was."""
        (item,) = _html._mutation_view(mutation_report([mutation_record("M07_changed_source_hash",
                                                                        detected=None)])).mutations
        self.assertEqual((item.group, item.note), ("UNRESOLVED", "executed, but no detection result is recorded"))

    def test_skipped_mutations_never_fire(self) -> None:
        record = ruled_record("M15_skipped_required_checker", [EXPECTED_FIRE])
        record["execution_state"] = "SKIPPED"
        (item,) = _html._mutation_view(mutation_report([record])).mutations
        self.assertEqual((item.group, item.firing), ("SKIPPED", "NOT EXECUTED"))

    def test_a_sensitivity_figure_the_records_do_not_give_is_withheld(self) -> None:
        report = mutation_report(detected_records(), sensitivity={"fraction": "3/3", "decimal": "1.0000"})
        view = _html._mutation_view(report)
        self.assertIsNone(view.sensitivity)
        self.assertIn("the report states sensitivity 3/3, but its records give 2/3; no figure is shown",
                      view.discrepancies)
        text = Page(render(DOCS["pass"], report)).text("#mutations")
        self.assertIn("Sensitivity none", text)
        self.assertNotIn("1.0000", text)

    def test_unknown_counts_read_unknown(self) -> None:
        report = mutation_report(detected_records(), executed_mutations=3)
        source = render(DOCS["pass"], report)
        self.assertIn('<dt>Detected</dt><dd class="unknown">unknown</dd>', source)
        self.assertIn("<dt>Executed</dt><dd>3</dd>", source)

    def test_only_a_disagreement_is_highlighted(self) -> None:
        """A record's own diagnostic is an ordinary line; the warning highlight is kept for contradictions."""
        record = ruled_record("M03_wrong_detector", [fired("check:row_count", "FAIL")])
        record["diagnostics"] = ["synthetic operator diagnostic"]
        source = render(DOCS["pass"], mutation_report([record]))
        notes = re.findall(r'<div class="cell-note">([^<]*)</div>', source)
        self.assertEqual(len(notes), 1)
        self.assertIn("the expected detector is not among the recorded fired detectors", notes[0])
        self.assertIn('<div class="cell-sub">synthetic operator diagnostic</div>', source)

    def test_long_identifiers_may_wrap_and_stay_escaped(self) -> None:
        self.assertEqual(_html._breakable("M20_a<b"), '<code class="brk">M20_<wbr>a&lt;b</code>')
        self.assertEqual(_html._breakable("check:a&b_c"), '<code class="brk">check:<wbr>a&amp;b_<wbr>c</code>')
        source = render(DOCS["pass"], REPORTS["valid"])
        self.assertIn("M20_<wbr>metadata_<wbr>change_<wbr>under_<wbr>unchanged_<wbr>pass_<wbr>summary", source)
        self.assertEqual(Page(source).problems, [])


# ---------------------------------------------------------------------------
# Checker controls: falsifier witnesses, the run canary, the comparator, resolver canaries
# ---------------------------------------------------------------------------


def check_of(document: dict[str, Any], kind: str) -> dict[str, Any]:
    """The document's first check result of ``kind`` (editable when ``document`` is a private copy)."""
    return next(check for check in document["checks"] if check["kind"] == kind)


def facet(plane: Any, name: str) -> Any:
    (found,) = [item for item in plane.facets if item.name == name]
    return found


class WitnessTests(unittest.TestCase):
    """Extension #1 as the page shows it: every PASS carries the known-bad case it rejected."""

    def test_every_pass_shows_the_known_bad_case_it_rejected(self) -> None:
        page = Page(page_source("pass"))
        table = page.text("data-equivalent-of=controls")
        for check in DOCS["pass"]["checks"]:
            (case,) = check["evidence"]["falsifiers"]
            for fact in (check["check_id"], case["case_id"], case["description"]):
                self.assertIn(fact, table)
            self.assertIn(_html._breakable(case["control_id"]), page.source)
        self.assertEqual({row.witness.label for row in _html._lattice_rows(doc())}, {"WITNESSED"})
        self.assertIn(">6 could fail<", svg_of(page.source, "lattice"))
        self.assertIn('<div class="stat-value">6 / 6</div>', page.source)
        self.assertEqual(states(planes(doc())[1])["Falsifier witnesses"], "LIT")
        self.assertEqual({row.outcome for row in _html._falsifier_rows(doc())}, {"REJECTED"})

    def test_falsifier_invocations_are_placed_where_the_ledger_ran_them(self) -> None:
        """Requirement 21 for controls: each witness points to the invocation the ledger recorded for it."""
        started = {
            entry["check_id"]: entry["invocation_id"] for entry in RUNS["pass"].ledger.entries
            if entry["result"] == "STARTED"
        }
        view = _html._ledger_view(doc())
        self.assertTrue(view.complete, view.note)
        for position, check in enumerate(DOCS["pass"]["checks"]):
            for number, case in enumerate(check["evidence"]["falsifiers"]):
                self.assertEqual(view.falsifier_invocations[(position, number)], started[case["control_id"]])
        text = Page(page_source("pass")).text("#controls")
        for invocation in view.falsifier_invocations.values():
            self.assertIn(f"invocation {invocation}, derived from its ledger position", text)

    def test_a_refuted_witness_is_a_proven_miss(self) -> None:
        document = doc()
        check = document["checks"][0]
        check["evidence"]["falsifiers"][0].update(
            outcome="ACCEPTED", actual={"verdict": "PASS", "reason": "VERIFIED", "execution_state": "CHECKED"}
        )
        check["evidence"]["falsification"] = "REFUTED"
        check.update(verdict="FAIL", reason="BLIND_SPOT")
        self.assertEqual(states(planes(document)[1])["Falsifier witnesses"], "BROKEN")
        witness = {row.check_id: row.witness.label for row in _html._lattice_rows(document)}
        self.assertEqual(witness[check["check_id"]], "REFUTED")
        (row,) = [item for item in _html._falsifier_rows(document) if item.label == check["check_id"]]
        self.assertEqual(row.outcome, "ACCEPTED")
        self.assertIn('class="dumbbell t-critical missed"', svg_of(render(document), "controls"))

    def test_a_relabelled_case_is_not_a_witness(self) -> None:
        """A case that still says REJECTED although it recorded PASS is shown as what its results give."""
        document = doc()
        check = document["checks"][0]
        check["evidence"]["falsifiers"][0]["actual"] = {"verdict": "PASS", "reason": "VERIFIED",
                                                         "execution_state": "CHECKED"}
        self.assertFalse(_html._witnessed(check))
        self.assertIn(
            f"required check {check['check_id']} is PASS without a falsifier witness (falsification WITNESSED)",
            gaps(document),
        )
        source = render(document)
        self.assertIn("the case records REJECTED", source)
        self.assertIn('id="contradiction-heading"', source)
        self.assertEqual(states(planes(document)[1])["Falsifier witnesses"], "PARTIAL")
        witness = {row.check_id: row.witness.label for row in _html._lattice_rows(document)}
        self.assertEqual(witness[check["check_id"]], "NO REJECTED CASE")

    def test_a_pass_without_a_witness_record_is_unsupported(self) -> None:
        document = doc()
        check = document["checks"][0]
        del check["evidence"]["falsification"], check["evidence"]["falsifiers"]
        witness = {row.check_id: row.witness.label for row in _html._lattice_rows(document)}
        self.assertEqual(witness[check["check_id"]], "NOT RECORDED")
        self.assertIn(
            f"required check {check['check_id']} is PASS without a falsifier witness (falsification not recorded)",
            gaps(document),
        )
        self.assertIn('<div class="stat-value">5 / 6</div>', render(document))

    def test_a_case_run_by_another_checker_is_flagged(self) -> None:
        document = doc()
        document["checks"][0]["evidence"]["falsifiers"][0]["checker_sha256"] = "0" * 64
        text = Page(render(document)).text("data-equivalent-of=controls")
        self.assertIn("NO: checker_sha256 differs or is missing", text)

    def test_a_check_with_no_case_says_why(self) -> None:
        document = doc()
        check = document["checks"][0]
        check["evidence"].update(falsification="NO_GENERATOR", falsifiers=[])
        check.update(verdict="ABSTAIN", reason="BLIND_SPOT")
        self.assertIn("no negative-control generator exists for this kind",
                      Page(render(document)).text("data-equivalent-of=controls"))
        witness = {row.check_id: row.witness.label for row in _html._lattice_rows(document)}
        self.assertEqual(witness[check["check_id"]], "NO_GENERATOR")

    def test_a_witness_summary_that_disagrees_with_the_checks_is_reported(self) -> None:
        document = doc()
        document["controls"]["falsifiers"]["WITNESSED"] = []
        self.assertIn("The run's witness summary disagrees with its checks", render(document))
        self.assertNotIn("witness summary disagrees", page_source("pass"))


class RunControlsTests(unittest.TestCase):
    """The run-level controls (17.5, 17.6, 17.14), judged by what they had to do, never assumed."""

    def test_the_canary_twins_and_the_comparator_show_their_invocations(self) -> None:
        controls = DOCS["pass"]["controls"]
        text = Page(page_source("pass")).text("#controls")
        for twin in ("must_fail", "must_pass"):
            self.assertIn(controls["canary"][twin]["invocation_id"], text)
        self.assertIn(controls["comparator_self_test"]["invocation_id"], text)
        rows = _html._canary_rows(controls) + _html._comparator_rows(controls)
        self.assertEqual(len(rows), 5)
        self.assertEqual({row.outcome for row in rows}, {"AS REQUIRED"})
        performance = states(planes(doc())[1])
        self.assertEqual((performance["Run canary"], performance["Comparator self-test"]), ("LIT", "LIT"))

    def test_a_canary_that_passed_its_planted_duplicate_is_a_proven_miss(self) -> None:
        document = doc()
        canary = document["controls"]["canary"]
        canary["must_fail"].update(verdict="PASS", reason="VERIFIED")
        canary["holds"] = False
        self.assertEqual(_html._canary_rows(document["controls"])[0].outcome, "NOT AS REQUIRED")
        self.assertEqual(states(planes(document)[1])["Run canary"], "BROKEN")
        self.assertIn("the run canary records holds false, not true (controls.canary)", gaps(document))

    def test_the_comparator_is_judged_against_the_contract_not_its_own_record(self) -> None:
        document = doc()
        pairs = document["controls"]["comparator_self_test"]["pairs"]
        (pair,) = [item for item in pairs if item["claim"] == "0.15"]
        pair.update(expected="EXACT", actual="EXACT")

        def row() -> Any:
            (found,) = [item for item in _html._comparator_rows(document["controls"])
                        if item.label == "claim 0.15 vs stored 0.14"]
            return found

        self.assertEqual(row().outcome, "NOT AS REQUIRED")
        self.assertIn("the contract requires DISAGREES", row().note)
        pairs.remove(pair)
        self.assertEqual(row().outcome, "NOT RECORDED")

    def test_missing_controls_stay_dark_and_a_pass_without_them_is_unsupported(self) -> None:
        document = doc()
        document["controls"] = None
        integrity, performance = planes(document)
        self.assertEqual((states(integrity)["Plan committed"], states(integrity)["Harness pins"]), ("DARK", "DARK"))
        self.assertEqual((states(performance)["Run canary"], states(performance)["Comparator self-test"]),
                         ("DARK", "DARK"))
        found = gaps(document)
        for gap in ("no PLAN is recorded in controls.plan", "the run canary is not recorded (controls.canary)",
                    "the comparator self-test is not recorded (controls.comparator_self_test)",
                    "the harness pins is not recorded (controls.pins)"):
            self.assertIn(gap, found)
        self.assertIn(">NOT RECORDED<", svg_of(render(document), "controls"))

    def test_resolver_canaries_are_shown_per_prefix(self) -> None:
        source = page_source("canary")
        evidence = check_of(DOCS["canary"], "citation_resolver")["evidence"]
        (prefix,) = evidence["canaries"]
        canary = evidence["canaries"][prefix]
        rows = _html._resolver_rows(DOCS["canary"])
        self.assertEqual([row.outcome for row in rows], ["RESOLVED"])
        text = Page(source).text("data-equivalent-of=controls")
        for fact in (canary["doi"], canary["detail"], f"prefix {prefix} (frozen)", "distrusted prefix"):
            self.assertIn(fact, text)
        self.assertIn('class="dumbbell t-critical missed"', svg_of(source, "controls"))
        self.assertNotIn("://", source, "a provenance URL is never echoed into the page")
        self.assertEqual(_html._resolver_rows(DOCS["pass"]), [])

    def test_a_relabelled_resolver_canary_still_resolves(self) -> None:
        document = doc("canary")
        evidence = check_of(document, "citation_resolver")["evidence"]
        for record in evidence["canaries"].values():
            record["holds"] = True
        self.assertEqual({row.outcome for row in _html._resolver_rows(document)}, {"RESOLVED"})


class DiscriminationTests(unittest.TestCase):
    """Extension #3 as the page shows it: how much of a nearby grid each numeric check would reject."""

    def numeric(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        return [check for check in document["checks"] if "discrimination_ratio" in check["evidence"]]

    def test_each_numeric_check_shows_how_much_of_its_grid_it_rejects(self) -> None:
        source = page_source("pass")
        numeric = self.numeric(DOCS["pass"])
        self.assertEqual(len(numeric), 2)
        bars = svg_of(source, "discrimination")
        lattice = Page(source).text("data-equivalent-of=lattice")
        for check in numeric:
            ratio = check["evidence"]["discrimination_ratio"]
            self.assertIn(f"{ratio['fraction']} = {ratio['decimal']}", bars)
            self.assertIn(f"discrimination {ratio['fraction']} = {ratio['decimal']}", lattice)
        weakest = DOCS["pass"]["controls"]["min_discrimination"]["check_id"]
        self.assertEqual(_html._weakest(_html._discriminations(doc())), weakest)
        self.assertEqual(bars.count("weakest PASS"), 1)
        self.assertNotIn('data-visual="discrimination"', page_source("empty"))

    def test_a_ratio_without_a_value_is_never_a_percentage(self) -> None:
        """Extension #23: a zero denominator has no value, so it is drawn empty and never read as 0% or 100%."""
        document = doc()
        check = self.numeric(document)[0]
        check["evidence"]["discrimination_ratio"] = {"numerator": 0, "denominator": 0, "state": "ZERO_DENOMINATOR",
                                                     "fraction": "0/0", "decimal": None, "exact": None}
        view = _html._ratio_view(check["evidence"]["discrimination_ratio"])
        self.assertFalse(view.defined)
        self.assertEqual(view.text(), "no value (ZERO_DENOMINATOR, 0/0 as counted)")
        bars = svg_of(render(document), "discrimination")
        self.assertIn('class="track undefined"', bars)
        self.assertNotIn("%", bars)

    def test_a_ratio_whose_record_disagrees_with_its_counts_is_not_drawn(self) -> None:
        view = _html._ratio_view({"numerator": 20, "denominator": 21, "state": "DEFINED", "fraction": "20/21",
                                  "decimal": "0.5", "exact": False})
        self.assertFalse(view.defined)
        self.assertIn("the record's own decimal disagree with its counts", view.text())
        self.assertIsNone(_html._ratio_view({"numerator": 5, "denominator": 3}).ratio)
        self.assertEqual(_html._ratio_view(None).text(), "not recorded")

    def test_a_recorded_weakest_pass_that_the_checks_contradict_is_reported(self) -> None:
        document = doc()
        weakest = document["controls"]["min_discrimination"]["check_id"]
        other = next(check["check_id"] for check in self.numeric(document) if check["check_id"] != weakest)
        document["controls"]["min_discrimination"]["check_id"] = other
        self.assertIn(f"run.json records the weakest PASS as {other}, but its checks give {weakest}",
                      Page(render(document)).text("#discrimination"))

    def test_a_consistency_test_shows_its_grid(self) -> None:
        text = Page(page_source("grim")).text("data-equivalent-of=discrimination")
        test = check_of(DOCS["grim"], "claim_registry")["evidence"]["consistency"]["tests"][0]
        ratio = test["discrimination_ratio"]
        self.assertIn(f"{ratio['fraction']} = {ratio['decimal']}", text)
        self.assertIn(f"{test['claim_id']} {test['test']}: {test['outcome']}", text)
        self.assertIn(test["evidence"]["grid"], text)


class PlanTests(unittest.TestCase):
    """Extension #2 as the page shows it: the PLAN, and every planned item closed by what ran."""

    def test_every_planned_item_is_closed_by_a_recorded_invocation(self) -> None:
        items = _html._plan_items(doc())
        declared = [spec["id"] for spec in DOCS["pass"]["declared"]["checks"]]
        self.assertEqual([item.item_id for item in items], declared + list(PLANNED_CONTROLS))
        self.assertTrue(all(item.closed for item in items))
        page = Page(page_source("pass"))
        facts = page.text("data-equivalent-of=plan")
        self.assertIn(DOCS["pass"]["controls"]["plan"]["entry_sha256"], facts)
        self.assertIn("the manifest this run read", facts)
        self.assertIn(f"{len(items)} of {len(items)} planned item(s) closed", svg_of(page.source, "plan"))
        self.assertEqual(states(planes(doc())[0])["Plan committed"], "LIT")

    def test_an_unexecuted_planned_check_is_named(self) -> None:
        document = doc()
        document["checks"] = [check for check in document["checks"] if check["check_id"] != "snapshot"]
        text = Page(render(document)).text("#plan")
        self.assertIn("Planned but not closed by a terminal invocation in run.json", text)
        self.assertIn("snapshot (check): no result recorded", text)
        self.assertIn("OPEN", text)

    def test_a_violated_plan_closure_breaks_the_plan_and_names_its_gap(self) -> None:
        document = doc()
        (closure,) = [item for item in document["invariants"] if item["name"] == "plan_closure"]
        detail = "planned 'snapshot' has 0 invocation(s) and 0 terminal result(s); exactly one of each is required"
        closure.update(holds=False, detail=detail)
        plan = facet(planes(document)[0], "Plan committed")
        self.assertEqual(plan.state, "BROKEN")
        self.assertIn(detail, plan.detail)
        self.assertIn(detail, Page(render(document)).text("#plan"))

    def test_a_missing_plan_is_dark_and_unsupported(self) -> None:
        document = doc()
        document["controls"]["plan"] = None
        self.assertEqual(states(planes(document)[0])["Plan committed"], "DARK")
        self.assertIn("not recorded: nothing shows what the run committed to before its checks ran",
                      Page(render(document)).text("#plan"))
        self.assertIn("no PLAN is recorded in controls.plan", gaps(document))

    def test_a_plan_summary_that_disagrees_with_the_manifest_is_reported(self) -> None:
        document = doc()
        document["controls"]["plan"]["checks_planned"] = 5
        self.assertIn("the PLAN records checks_planned 5, but run.json declares 6 checks",
                      Page(render(document)).text("#plan"))


class ClaimJoinTests(unittest.TestCase):
    """Extension #6 as the page shows it: asserted actions joined to the sealed run they cite."""

    def test_the_four_outcomes_are_drawn_and_listed(self) -> None:
        source = page_source("claim_join")
        evidence = check_of(DOCS["claim_join"], "claim_join")["evidence"]
        figure = svg_of(source, "claim-join")
        for outcome in ("BACKED", "NARRATED", "CONTRADICTED", "ORPHANED"):
            self.assertIn(f"{outcome} \u00b7 {evidence['counts'][outcome]}", figure)
        text = Page(source).text("data-equivalent-of=claim-join")
        for assertion in evidence["assertions"]:
            self.assertIn(assertion["claim_id"], text)
            self.assertIn(assertion["detail"], text)
        for orphan in evidence["buckets"]["ORPHANED"]:
            self.assertIn(orphan, text)
        self.assertNotIn("disagree with its own records", source)
        self.assertNotIn('id="claims"', page_source("pass"))

    def test_counts_that_disagree_with_the_buckets_or_controls_are_reported(self) -> None:
        document = doc("claim_join")
        check_of(document, "claim_join")["evidence"]["counts"]["BACKED"] = 2
        text = Page(render(document)).text("#claims")
        self.assertIn("counts BACKED 2, but its bucket lists 1", text)
        self.assertIn("controls.claim_join records", text)

    def test_a_join_without_counts_reads_unknown_not_zero(self) -> None:
        document = doc("claim_join")
        del check_of(document, "claim_join")["evidence"]["counts"]
        self.assertIn("unknown: no counts recorded", Page(render(document)).text("#claims"))


class LedgerMapTests(unittest.TestCase):
    """Every ledger entry identified from run.json, and only when the identification tiles the seal."""

    def test_every_entry_is_identified_as_the_ledger_records_it(self) -> None:
        view = _html._ledger_view(doc())
        entries = RUNS["pass"].ledger.entries
        self.assertTrue(view.complete, view.note)
        self.assertEqual(list(view.entries), [entry["seq"] for entry in entries])
        unverdicted = set()
        for entry in entries:
            shown = view.entries[entry["seq"]]
            if entry["result"] == "PLAN":
                self.assertEqual((shown.phase, shown.family, entry["seq"]), ("PLAN", "plan", 1))
                continue
            self.assertEqual((shown.owner, shown.invocation), (entry["check_id"], entry["invocation_id"]))
            self.assertEqual(shown.phase == "STARTED", entry["result"] == "STARTED")
            if shown.phase == "TERMINAL" and shown.verdict is None:
                unverdicted.add(shown.owner)
            elif shown.phase == "TERMINAL":
                self.assertEqual(shown.verdict, entry["verdict"])
        self.assertEqual(unverdicted, {"control:comparator"}, "only the comparator records no verdict word")
        strip = svg_of(page_source("pass"), "ledger")
        self.assertIn('class="link-plan"', strip)
        self.assertEqual(strip.count('class="link-falsifier"'), 12)

    def test_a_derivation_that_does_not_tile_the_seal_is_not_used(self) -> None:
        document = doc()
        document["checks"][0]["evidence"]["falsifiers"] = []  # the ledger still holds that case's two entries
        view = _html._ledger_view(document)
        self.assertFalse(view.complete)
        self.assertIn("not the 31 sealed", view.note)
        self.assertEqual(view.falsifier_invocations, {})
        self.assertEqual({entry.phase for entry in view.entries.values()}, {"STARTED"})
        source = render(document)
        self.assertIn("invocation not derivable from run.json", Page(source).text("#controls"))
        self.assertNotIn('class="link-falsifier"', svg_of(source, "ledger"))


class MutationV2Tests(unittest.TestCase):
    """Report v2 (17.12): conservation recomputed from the buckets, M00 apart, blind spots by PIE stage."""

    def test_conservation_is_recomputed_from_the_buckets(self) -> None:
        report = REPORTS["valid"]
        conservation = _html._mutation_view(report).conservation
        self.assertIs(conservation.holds, True)
        self.assertEqual((conservation.generated, conservation.executed),
                         (report["generated_mutations"], report["executed_mutations"]))
        page = Page(render(DOCS["pass"], report))
        text = page.text("data-equivalent-of=conservation")
        self.assertIn(f"{report['generated_mutations']} = executed {report['executed_mutations']}", text)
        self.assertIn("holds (recomputed); the report records holds", text)
        self.assertIn("conservation", {attributes.get("data-visual") for _, attributes in page.elements})

    def test_a_bucket_that_lost_a_mutant_breaks_conservation_whatever_the_report_says(self) -> None:
        report = copy.deepcopy(REPORTS["valid"])
        lost = report["buckets"]["DETECTED"].pop()
        view = _html._mutation_view(report)
        self.assertIs(view.conservation.holds, False)
        self.assertTrue(any("records conservation holds, but its buckets do not" in text
                            for text in view.discrepancies))
        self.assertIn(f"{lost} records status DETECTED, but bucket DETECTED does not list it",
                      view.conservation.problems)

    def test_m00_is_shown_apart_and_never_counted(self) -> None:
        report = copy.deepcopy(REPORTS["valid"])
        source = render(DOCS["pass"], report)
        self.assertIn("M00 forced detection", svg_of(source, "conservation"))
        self.assertNotIn("M00", svg_of(source, "mutations"))
        self.assertIn(report["forced_detection"]["target"], Page(source).text("data-equivalent-of=conservation"))
        report["forced_detection"]["detected"] = False
        self.assertIn("NOT detected", svg_of(render(DOCS["pass"], report), "conservation"))

    def test_a_report_without_buckets_shows_no_identity(self) -> None:
        source = render(DOCS["pass"], mutation_report(detected_records()))
        self.assertIn("records no buckets and no forced detection", source)
        self.assertNotIn('data-visual="conservation"', source)

    def test_blind_spots_sit_on_the_pie_stage_they_reached(self) -> None:
        records = []
        for number, stage in enumerate(("NOT_READ", "PROPAGATED_NOT_CHECKED", "PROPAGATED_NOT_CHECKED"), start=1):
            record = mutation_record(f"M{number:02}_synthetic_blind_spot", detected=False)
            record["pie_stage"] = stage
            records.append(record)
        records.append(mutation_record("M09_synthetic_escape", detected=False))
        source = render(DOCS["pass"], mutation_report(records))
        stars = svg_of(source, "mutations")
        for label in ("NOT_READ \u00b7 1", "READ_NOT_INFECTED \u00b7 0", "PROPAGATED_NOT_CHECKED \u00b7 2",
                      "NO STAGE RECORDED \u00b7 1"):
            self.assertIn(label, stars)
        table = Page(source).text("data-equivalent-of=mutations")
        self.assertIn("PROPAGATED_NOT_CHECKED a check saw the change and still passed "
                      "M02_synthetic_blind_spot, M03_synthetic_blind_spot", table)


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


def frontier_poisoned() -> tuple[dict[str, Any], list[str]]:
    """A PASS document with a distinct hostile value in every frontier field the page shows in full.

    Returns the document and the values, so a test can check that each one
    reached the page, and reached it escaped. Tags avoid ``_`` and ``:``,
    the characters after which identifiers get a line-break opportunity.
    """
    shown: list[str] = []

    def hostile(tag: str) -> str:
        shown.append(f"{HOSTILE}#{tag}")
        return shown[-1]

    document = doc()
    controls = document["controls"]
    controls["plan"].update(entry_sha256=hostile("planentry"), manifest_sha256=hostile("planmanifest"))
    controls["canary"]["must_fail"].update(invocation_id=hostile("canaryinvocation"), verdict=hostile("canaryverdict"),
                                           reason=hostile("canaryreason"))
    controls["comparator_self_test"]["invocation_id"] = hostile("comparatorinvocation")
    controls["comparator_self_test"]["pairs"][0]["actual"] = hostile("comparatoractual")
    controls["pins"].update(changed=[hostile("pinchanged")],
                            writes=[{"path": hostile("pinwrite"), "action": "write", "event": "open"}])
    controls["min_discrimination"]["check_id"] = hostile("weakest")
    controls["verdict_transitions"] = [{"step": 1, "source": hostile("source"), "before": hostile("before"),
                                        "after": hostile("after"), "reason": hostile("transitionreason")}]
    witnessed = document["checks"][0]
    witnessed["evidence"]["falsifiers"][0].update(
        case_id=hostile("caseid"), description=hostile("description"), control_id=hostile("controlid"),
        expected={"verdict": hostile("expectedverdict"), "reason": hostile("expectedreason")},
    )
    numeric = next(check for check in document["checks"] if "discrimination_ratio" in check["evidence"])
    numeric["evidence"]["discrimination_ratio"]["state"] = hostile("ratiostate")
    numeric["evidence"]["comparisons"][0]["key"] = hostile("comparisonkey")
    skipped = document["checks"][1]
    skipped.update(execution_state="SKIPPED", verdict="ABSTAIN", reason="INSUFFICIENT_EVIDENCE")
    skipped["evidence"]["skip_justification"] = hostile("skiplabel")
    extra = {"version": "1", "required": False, "execution_state": "CHECKED", "verdict": "ABSTAIN",
             "reason": "UNVERIFIED", "failure_modes": [], "rows_examined": 1, "inputs": [], "diagnostics": [],
             "invocation_id": None}
    document["checks"].append({**extra, "check_id": "synthetic-join", "kind": "claim_join", "evidence": {
        "assertions": [{"claim_id": hostile("claimid"), "kind": hostile("claimkind"), "cites": hostile("cites"),
                        "outcome": hostile("outcome"), "detail": hostile("claimdetail")}],
        "buckets": {"ORPHANED": [hostile("orphan")]},
        "counts": {"ORPHANED": 1},
        "chain": {"intact": True, "problems": [hostile("chainproblem")]},
        "sealed_run": {"path": "sealed", "seal": {"run_id": hostile("sealedrun")}},
    }})
    document["checks"].append({**extra, "check_id": "synthetic-resolver", "kind": "citation_resolver", "evidence": {
        "canaries": {hostile("prefix"): {"doi": hostile("doi"), "state": "DOI_NOT_RESOLVED_AT_CAPTURE", "holds": True,
                                         "detail": hostile("canarydetail"),
                                         "provenance": {"retrieved_at": hostile("retrieved")}}},
        "distrusted_prefixes": [hostile("distrusted")],
    }})
    return document, shown


class EscapingTests(unittest.TestCase):
    def assert_shown_escaped(self, source: str, values: list[str]) -> None:
        self.assert_inert(source)
        for value in values:
            self.assertIn(html.escape(value, quote=True), source, value[len(HOSTILE):])

    def test_every_frontier_value_is_shown_escaped(self) -> None:
        document, values = frontier_poisoned()
        self.assert_shown_escaped(render(document), values)

    def test_every_mutation_report_v2_value_is_shown_escaped(self) -> None:
        values: list[str] = []

        def hostile(tag: str) -> str:
            values.append(f"{HOSTILE}#{tag}")
            return values[-1]

        report = copy.deepcopy(REPORTS["valid"])
        report["forced_detection"].update(target=hostile("target"), detector=hostile("detector"),
                                          fired=[{"detector": hostile("fired"), "status": "FAIL"}])
        report["buckets"]["DETECTED"].append(hostile("bucketmember"))
        report["buckets"][hostile("bucketname")] = []
        report["conservation"]["disjoint"] = hostile("disjoint")
        record = mutation_record("M01_synthetic_blind_spot", detected=False)
        record.update(status=hostile("status"), pie_stage=hostile("stage"))
        report["mutations"].append(record)
        self.assert_shown_escaped(render(DOCS["pass"], report), values)

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

    def test_redaction_is_never_reused_from_an_earlier_render(self) -> None:
        """Cleaned text is memoized for one render only: a secret set between two renders is still redacted."""
        value = "synthetic-rotating-secret-7b1e"
        document = doc()
        document["manifest"]["run_label"] = value
        self.assertIn(value, render(document))
        self.assertIsNone(_html._CLEANED.get())
        with mock.patch.dict(os.environ, {"SCIENCE_GATE_HTML_TEST_TOKEN": value}):
            self.assertNotIn(value, render(document))
        self.assertIsNone(_html._CLEANED.get())


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
        for name in ("empty", "missing", "hash", "deleted", "error"):
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
        """Requirement 13 for the page: an interpreter with another hash seed writes identical bytes.

        One child process is enough: its seed is pinned to a value this
        process does not use, and its page is compared with this process's.
        """
        report = mutation_report(detected_records())
        case = _WORKSPACE[0] / "determinism-case.json"
        case.write_text(json.dumps({"run": DOCS["pass"], "mutation": report}), encoding="utf-8")
        seed = "0" if os.environ.get("PYTHONHASHSEED") == "4242" else "4242"
        environment = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(SRC_DIR), "PYTHONDONTWRITEBYTECODE": "1"}
        completed = subprocess.run(
            [sys.executable, "-c", _RENDER_SCRIPT, str(case)], env=environment, capture_output=True, timeout=120
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        self.assertEqual(completed.stdout, render(DOCS["pass"], report).encode("utf-8"))


class LargeDocumentTests(unittest.TestCase):
    def test_figures_draw_a_prefix_and_tables_keep_every_row(self) -> None:
        """A figure says how much it left out; its text equivalent never leaves anything out."""
        document = doc()
        check, spec = document["checks"][0], document["declared"]["checks"][0]
        record = document["accounting"]["inputs"][0]
        document["checks"] = [dict(check, check_id=f"synthetic-check-{n:03}") for n in range(90)]
        document["declared"]["checks"] = [dict(spec, id=f"synthetic-check-{n:03}") for n in range(90)]
        document["accounting"]["inputs"] = [dict(record, id=f"synthetic-input-{n:03}") for n in range(45)]
        document["invariants"] += [{"name": f"synthetic_invariant_{n:03}", "applicable": False, "holds": None,
                                    "detail": "synthetic"} for n in range(55)]
        report = mutation_report([mutation_record(f"M{n:03}-synthetic") for n in range(160)])
        source = render(document, report)
        self.assertIn("10 more check(s) are listed in the table.", svg_of(source, "lattice"))
        self.assertIn("5 more input(s) are listed in the table.", svg_of(source, "accounting"))
        # The contract invariants plus 55 synthetic ones, against a ring of _html._MAX_RING_SEGMENTS segments.
        hidden = len(INVARIANT_NAMES) + 55 - _html._MAX_RING_SEGMENTS
        self.assertIn(f"{hidden} more in the list", svg_of(source, "invariants"))
        self.assertIn("10 more in the table", svg_of(source, "mutations"))
        page = Page(source)
        self.assertIn("synthetic-check-089", page.text("data-equivalent-of=lattice"))
        self.assertIn("synthetic-input-044", page.text("#inputs"))
        self.assertIn("synthetic_invariant_054", page.text("data-equivalent-of=invariants"))
        self.assertIn("M159-synthetic", page.text("data-equivalent-of=mutations"))


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
        self.assertIn("signature UNSIGNED \u00b7 no signature to verify", page.text("#reverification"))
        self.assertIn('<dt>Invariant <code class="brk">ledger_<wbr>chain_<wbr>intact</code></dt>', page.source)
        self.assertIn("LIT Re-verification receipt, ledger chain and run.json re-verified from disk",
                      page.text("data-equivalent-of=hologram"))
        self.assertNotIn("Re-verification failed", page.source)


if __name__ == "__main__":
    unittest.main()
