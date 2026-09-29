"""Tests for the three citation layers and the resolver adapters (ARCHITECTURE.md section 9).

Everything here is synthetic: invented titles and author names, DOIs under
the 10.5555 test prefix, and resolver URLs under the reserved ``.invalid``
domain. No test touches the network. Live lookups go through injected
openers, and the fixture tests also make every socket connection fail, so an
accidental network call would fail loudly instead of quietly succeeding.
"""

from __future__ import annotations

import copy
import http.client
import io
import json
import os
import subprocess
import sys
import unittest
import urllib.error
from pathlib import Path
from typing import Any, Callable
from unittest import mock

from _helpers import FIXED_TIME, REPO_ROOT, SRC_DIR, TempDirTestCase

from science_gate._canonical import sha256_bytes, strict_loads
from science_gate.adapters import frozen as frozen_adapter
from science_gate.adapters import live as live_adapter
from science_gate.adapters.frozen import FROZEN_KEYS, FROZEN_SCHEMA, OUTCOMES, RECORD_KEYS, parse_frozen
from science_gate.adapters.records import (
    AUTHOR_KEYS,
    PROVENANCE_FIELDS,
    WORK_KEYS,
    RecordFormatError,
    Resolution,
    normalize_doi,
    parse_work,
    provenance_problems,
)
from science_gate.citations import (
    CITATION_KEYS,
    CLAIMED_STATUSES,
    DISPOSITIONS,
    ENTRIES_KEYS,
    ENTRIES_SCHEMA,
    INVOCATION_KEYS,
    LOG_ENTRY_KEYS,
    LOG_KEYS,
    LOG_REQUIRED_KEYS,
    LOG_SCHEMA,
    VERIFIER_KEYS,
    Defect,
    normalize_text,
)
from science_gate.manifests import IDENTIFIER_PATTERN
from science_gate.models import (
    ExecutionState,
    FailureMode,
    MetadataState,
    Reason,
    ResolverState,
    Status,
)
from science_gate.receipts import HMAC_KEY_FILE_ENV
from science_gate.verifier import NetworkPolicy, VerificationRun, verify

FIXTURES = REPO_ROOT / "fixtures" / "citations"
FIXTURE_NAMES = (
    "all-good",
    "conflated-entry",
    "missing-from-frozen",
    "narrated-log",
    "nonexistent-doi",
    "target-mismatch",
    "wrong-author",
)
CITATION_KINDS = ("verification_log", "citation_resolver", "citation_metadata")
CAPTURED_AT = "2026-02-14T09:00:00Z"
OBSERVATIONS = "observation_id,site,reading\nOBS-0001,Site-Alpha,4.20\nOBS-0002,Site-Beta,3.75\n"
DIGEST = "ab" * 32


# ---------------------------------------------------------------------------
# Synthetic documents
# ---------------------------------------------------------------------------


def author(family: str, given: str | None = None) -> dict[str, Any]:
    return {"family": family, "given": given}


def work(suffix: str, title: str, *authors: dict[str, Any], **fields: Any) -> dict[str, Any]:
    document = {
        "doi": f"10.5555/sgate.test.{suffix}",
        "title": title,
        "authors": list(authors),
        "year": 2031,
        "journal": "Synthetic Fixture Letters",
        "volume": "12",
        "issue": "3",
    }
    document.update(fields)
    return document


WORK_A = work("0001", "Calibrating invented sensors on a fictional plateau", author("Alphatest", "Ada"),
              author("Gammatest", "Cy"))
WORK_B = work("0002", "A placeholder survey of imaginary wetland counts", author("Betatest", "Bo"),
              author("Alphatest", "Ada"), year=2032, journal="Invented Methods Quarterly", volume="4", issue="1")
WORK_C = work("0003", "Nonexistent lattice effects in a made-up alloy", author("Deltatest", "Dee"), year=2030,
              journal="Journal of Fabricated Results", volume="7", issue="2")
WORK_D = work("0004", "Redirect target for a synthetic resolver test", author("Lambdatest", "Kit"), year=2035)


def cite(citation_id: str, base: dict[str, Any], **changes: Any) -> dict[str, Any]:
    entry = {"citation_id": citation_id, **copy.deepcopy(base)}
    entry.update(changes)
    return entry


def provenance(request: str) -> dict[str, Any]:
    return {
        "retrieved_at": CAPTURED_AT,
        "request_url_or_query": request,
        "response_sha256": sha256_bytes(request.encode("utf-8")),
        "resolver_identity": "synthetic-test-resolver",
        "resolver_schema_version": "test-1",
        "live_refresh_performed": False,
    }


def found(requested: str, returned: dict[str, Any] | None = None, **changes: Any) -> dict[str, Any]:
    record = {
        "doi": requested,
        "outcome": "FOUND",
        "http_status": 200,
        "work": copy.deepcopy(returned or next(item for item in ALL_WORKS if item["doi"] == requested)),
        **provenance(f"https://resolver.invalid/works/{requested}"),
    }
    record.update(changes)
    return record


def not_found(requested: str) -> dict[str, Any]:
    return {
        "doi": requested,
        "outcome": "NOT_FOUND",
        "http_status": 404,
        "work": None,
        **provenance(f"https://resolver.invalid/works/{requested}"),
    }


ALL_WORKS = (WORK_A, WORK_B, WORK_C, WORK_D)


def entries_document(*items: dict[str, Any]) -> dict[str, Any]:
    return {"schema": ENTRIES_SCHEMA, "citations": list(items)}


def frozen_document(*records: dict[str, Any]) -> dict[str, Any]:
    return {"schema": FROZEN_SCHEMA, "records": list(records)}


def invocation(invocation_id: str, citation_id: str, **changes: Any) -> dict[str, Any]:
    item = {
        "invocation_id": invocation_id,
        "citation_id": citation_id,
        "request": f"https://resolver.invalid/works/{citation_id}",
        "response_sha256": DIGEST,
        "retrieved_at": "2026-02-14T09:05:00Z",
    }
    item.update(changes)
    return {name: value for name, value in item.items() if value is not None}


def log_document(
    entries: list[tuple[str, str]], invocations: list[dict[str, Any]] | None, claimed: int | None = None
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema": LOG_SCHEMA,
        "claimed_verified": sum(1 for _, status in entries if status == "VERIFIED") if claimed is None else claimed,
        "verifier": {"name": "synthetic-citation-checker", "version": "0.0-test"},
        "entries": [{"citation_id": citation_id, "claimed_status": status} for citation_id, status in entries],
    }
    if invocations is not None:
        document["invocations"] = invocations
    return document


def good_log(*citation_ids: str) -> dict[str, Any]:
    ids = citation_ids or ("C1", "C2", "C3")
    return log_document(
        [(citation_id, "VERIFIED") for citation_id in ids],
        [invocation(f"inv-{index}", citation_id) for index, citation_id in enumerate(ids, start=1)],
    )


def csl(doi: str, **changes: Any) -> dict[str, Any]:
    """A synthetic CSL JSON record, with a field the adapter must not keep."""
    document = {
        "DOI": doi.upper(),
        "title": ["Calibrating invented sensors on a fictional plateau"],
        "author": [{"family": "Alphatest", "given": "Ada"}, {"literal": "Gammatest"}],
        "issued": {"date-parts": [[2031, 4, 1]]},
        "container-title": "Synthetic Fixture Letters",
        "volume": "12",
        "issue": 3,
        "abstract": "synthetic abstract that must not be kept",
    }
    document.update(changes)
    return document


# ---------------------------------------------------------------------------
# Network stand-ins
# ---------------------------------------------------------------------------


class FakeResponse:
    """A response object as an injected opener returns it; records whether it was closed."""

    def __init__(self, body: bytes, status: int = 200, *, status_attribute: bool = True) -> None:
        self._body = body
        self._status = status
        if status_attribute:
            self.status = status
        self.closed = False

    def getcode(self) -> int:
        return self._status

    def read(self, amount: int = -1) -> bytes:
        return self._body if amount < 0 else self._body[:amount]

    def close(self) -> None:
        self.closed = True


class ScriptedOpener:
    """Answers each request from a script and records every call. Never opens a socket."""

    def __init__(self, answer: FakeResponse | BaseException | Callable[[Any], Any]) -> None:
        self.answer = answer
        self.calls: list[tuple[Any, Any]] = []

    def __call__(self, request: Any, timeout: Any = None) -> Any:
        self.calls.append((request, timeout))
        if isinstance(self.answer, BaseException):
            raise self.answer
        if isinstance(self.answer, FakeResponse):
            return self.answer
        return self.answer(request)


def failing_opener() -> ScriptedOpener:
    return ScriptedOpener(OSError("synthetic: the network is unavailable in tests"))


def live_policy(opener: Any) -> NetworkPolicy:
    return NetworkPolicy(live=True, opener=opener)


def block_sockets(test: unittest.TestCase) -> None:
    """Make any socket connection in this test raise, so a network call cannot pass silently."""

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a citation test attempted a network connection")

    for target in ("socket.socket.connect", "socket.socket.connect_ex", "socket.create_connection"):
        patcher = mock.patch(target, refuse)
        patcher.start()
        test.addCleanup(patcher.stop)


# ---------------------------------------------------------------------------
# Adapter records
# ---------------------------------------------------------------------------


class DoiNormalizationTests(unittest.TestCase):
    def test_prefixes_and_ascii_case_are_normalized(self) -> None:
        for written in (
            "10.5555/SGATE.test.0001",
            " doi:10.5555/sgate.test.0001 ",
            "DOI:10.5555/sgate.test.0001",
            "https://doi.org/10.5555/sgate.test.0001",
            "HTTP://DX.DOI.ORG/10.5555/Sgate.Test.0001",
        ):
            with self.subTest(written=written):
                self.assertEqual(normalize_doi(written), "10.5555/sgate.test.0001")

    def test_only_ascii_letters_are_folded(self) -> None:
        self.assertEqual(normalize_doi("10.5555/ÄBC"), "10.5555/Äbc")

    def test_non_dois_are_refused(self) -> None:
        for value in (None, 105555, "", "10.55/x", "10.5555/", "10.5555/has space", "11.5555/x", "sgate.test.0001"):
            with self.subTest(value=value):
                self.assertIsNone(normalize_doi(value))


class WorkParsingTests(unittest.TestCase):
    def test_a_work_is_validated_and_normalized(self) -> None:
        parsed = parse_work({**WORK_B, "year": "2032", "volume": 4, "issue": None}, "work")
        self.assertEqual(
            (parsed.doi, parsed.year, parsed.volume, parsed.issue), ("10.5555/sgate.test.0002", "2032", "4", None)
        )
        self.assertEqual([item.display() for item in parsed.authors], ["Betatest, Bo", "Alphatest, Ada"])

    def test_identifying_fields_are_required(self) -> None:
        for missing in ("doi", "title", "authors"):
            with self.subTest(missing=missing), self.assertRaises(RecordFormatError):
                parse_work({key: value for key, value in WORK_A.items() if key != missing}, "work")

    def test_malformed_works_are_refused(self) -> None:
        for change in (
            {"doi": "not-a-doi"},
            {"title": "   "},
            {"authors": []},
            {"authors": [{"given": "Ada"}]},
            {"authors": [{"family": "Alphatest", "middle": "X"}]},
            {"year": 31},
            {"year": "MMXXXI"},
            {"year": True},
            {"volume": -1},
            {"abstract": "extra fields are refused, not ignored"},
        ):
            with self.subTest(change=change), self.assertRaises(RecordFormatError):
                parse_work({**WORK_A, **change}, "work")


class ProvenanceTests(unittest.TestCase):
    def test_complete_provenance_has_no_problems(self) -> None:
        self.assertEqual(provenance_problems(provenance("q")), ())

    def test_each_missing_field_is_named(self) -> None:
        for name in PROVENANCE_FIELDS:
            with self.subTest(field=name):
                record = {key: value for key, value in provenance("q").items() if key != name}
                self.assertEqual(provenance_problems(record), (f"MISSING_PROVENANCE: {name}",))

    def test_malformed_fields_are_named(self) -> None:
        malformed = {
            "retrieved_at": "2026-02-14 09:00",
            "request_url_or_query": " ",
            "response_sha256": "ABC",
            "resolver_identity": 7,
            "resolver_schema_version": "",
            "live_refresh_performed": "false",
        }
        for name, value in malformed.items():
            with self.subTest(field=name):
                problems = provenance_problems({**provenance("q"), name: value})
                self.assertEqual(problems, (f"INVALID_PROVENANCE: {name}",))

    def test_a_resolution_carries_a_work_exactly_when_it_reached_one(self) -> None:
        reached = parse_work(WORK_A, "work")
        with self.assertRaises(ValueError):
            Resolution("10.5555/x", ResolverState.DOI_RESOLVED, "frozen")
        with self.assertRaises(ValueError):
            Resolution("10.5555/x", ResolverState.SOURCE_UNAVAILABLE, "frozen", work=reached)
        with self.assertRaises(ValueError):
            Resolution("10.5555/x", ResolverState.SOURCE_UNAVAILABLE, "cache")


# ---------------------------------------------------------------------------
# Frozen adapter
# ---------------------------------------------------------------------------


class FrozenAdapterTests(unittest.TestCase):
    def resolve(self, doi: str, *records: dict[str, Any]) -> Resolution:
        return frozen_adapter.resolve(normalize_doi(doi), parse_frozen(frozen_document(*records)))

    def test_a_complete_record_resolves_with_all_provenance(self) -> None:
        answer = self.resolve(WORK_A["doi"], found(WORK_A["doi"]))
        self.assertEqual((answer.state, answer.source), (ResolverState.DOI_RESOLVED, "frozen"))
        self.assertEqual(answer.work.title, WORK_A["title"])
        self.assertEqual(answer.to_dict()["provenance"], provenance(f"https://resolver.invalid/works/{WORK_A['doi']}"))

    def test_missing_provenance_makes_that_record_source_unavailable(self) -> None:
        for name in PROVENANCE_FIELDS:
            with self.subTest(field=name):
                record = {key: value for key, value in found(WORK_A["doi"]).items() if key != name}
                answer = self.resolve(WORK_A["doi"], record, found(WORK_B["doi"]))
                self.assertEqual(answer.state, ResolverState.SOURCE_UNAVAILABLE)
                self.assertIsNone(answer.work, "an unresolved record must never supply a reference work")
                self.assertIn(f"MISSING_PROVENANCE: {name}", answer.diagnostics)
                self.assertIsNone(answer.to_dict()["provenance"][name])
                # The other record in the same set is unaffected.
                other = self.resolve(WORK_B["doi"], record, found(WORK_B["doi"]))
                self.assertEqual(other.state, ResolverState.DOI_RESOLVED)

    def test_a_captured_not_found_is_not_resolved_at_capture(self) -> None:
        answer = self.resolve("10.5555/sgate.test.9999", not_found("10.5555/sgate.test.9999"))
        self.assertEqual(answer.state, ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE)
        self.assertIsNone(answer.work)
        self.assertEqual(answer.http_status, 404)

    def test_absence_is_source_unavailable_never_not_found(self) -> None:
        answer = self.resolve("10.5555/sgate.test.9999", found(WORK_A["doi"]))
        self.assertEqual((answer.state, answer.source), (ResolverState.SOURCE_UNAVAILABLE, "none"))
        self.assertTrue(answer.diagnostics[0].startswith("NOT_IN_FROZEN_SET"))
        without_set = frozen_adapter.resolve("10.5555/sgate.test.0001", None, "NO_FROZEN_SET: synthetic")
        self.assertEqual(without_set.state, ResolverState.SOURCE_UNAVAILABLE)
        self.assertEqual(without_set.diagnostics, ("NO_FROZEN_SET: synthetic",))

    def test_a_resolver_error_at_capture_is_source_unavailable(self) -> None:
        record = {**found(WORK_A["doi"]), "outcome": "ERROR", "http_status": 503, "work": None}
        self.assertEqual(self.resolve(WORK_A["doi"], record).state, ResolverState.SOURCE_UNAVAILABLE)

    def test_a_different_returned_doi_is_a_target_mismatch(self) -> None:
        answer = self.resolve(WORK_A["doi"], found(WORK_A["doi"], WORK_D))
        self.assertEqual(answer.state, ResolverState.DOI_TARGET_MISMATCH)
        self.assertEqual(answer.work.doi, WORK_D["doi"])
        self.assertEqual(answer.to_dict()["returned_doi"], WORK_D["doi"])

    def test_self_contradicting_records_vouch_for_nothing(self) -> None:
        for record in (
            {**found(WORK_A["doi"]), "work": None},
            {**not_found(WORK_A["doi"]), "work": copy.deepcopy(WORK_A)},
            {**found(WORK_A["doi"]), "http_status": 404},
        ):
            with self.subTest(record=record["outcome"]):
                answer = self.resolve(WORK_A["doi"], record)
                self.assertEqual(answer.state, ResolverState.SOURCE_UNAVAILABLE)
                self.assertTrue(any(text.startswith("OUTCOME_CONFLICT") for text in answer.diagnostics))

    def test_structural_problems_refuse_the_whole_set(self) -> None:
        for document in (
            {"schema": "other/v1", "records": []},
            {"schema": FROZEN_SCHEMA},
            {"schema": FROZEN_SCHEMA, "records": {}},
            frozen_document({**found(WORK_A["doi"]), "body": "not allowed"}),
            frozen_document({**found(WORK_A["doi"]), "doi": "not-a-doi"}),
            frozen_document({**found(WORK_A["doi"]), "outcome": "MAYBE"}),
            frozen_document({**found(WORK_A["doi"]), "http_status": 700}),
            frozen_document({**found(WORK_A["doi"]), "work": {"title": "no doi"}}),
            frozen_document(found(WORK_A["doi"]), found("https://doi.org/10.5555/SGATE.TEST.0001", WORK_A)),
        ):
            with self.subTest(document=json.dumps(document)[:80]), self.assertRaises(RecordFormatError):
                parse_frozen(document)

    def test_reference_works_exclude_unusable_records_and_prefer_direct_captures(self) -> None:
        records = frozen_document(
            found(WORK_A["doi"], WORK_D),  # redirected to D
            found(WORK_D["doi"], {**WORK_D, "title": "Direct capture of the redirect target"}),
            {key: value for key, value in found(WORK_B["doi"]).items() if key != "retrieved_at"},
            not_found(WORK_C["doi"]),
        )
        works = parse_frozen(records).resolved_works()
        self.assertEqual([item.doi for item in works], [WORK_D["doi"]])
        self.assertEqual(works[0].title, "Direct capture of the redirect target")


# ---------------------------------------------------------------------------
# Live adapter
# ---------------------------------------------------------------------------


class LiveAdapterTests(TempDirTestCase):
    DOI = "10.5555/sgate.test.0001"

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()

    def test_it_refuses_unless_the_policy_is_live(self) -> None:
        opener = failing_opener()
        with self.assertRaises(live_adapter.LiveAccessRefused):
            live_adapter.resolve(self.DOI, NetworkPolicy(opener=opener))
        self.assertEqual(opener.calls, [])

    def test_every_network_failure_is_source_unavailable(self) -> None:
        failures = {
            "OSError": OSError("synthetic"),
            "URLError": urllib.error.URLError("synthetic resolver unreachable"),
            "TimeoutError": TimeoutError("synthetic timeout"),
            "ConnectionResetError": ConnectionResetError("synthetic reset"),
            "IncompleteRead": http.client.IncompleteRead(b"partial"),
            "ValueError": ValueError("synthetic bad URL"),
        }
        for name, failure in failures.items():
            with self.subTest(failure=name):
                answer = live_adapter.resolve(self.DOI, live_policy(ScriptedOpener(failure)))
                self.assertEqual((answer.state, answer.source), (ResolverState.SOURCE_UNAVAILABLE, "live"))
                self.assertTrue(answer.diagnostics[0].startswith(f"NETWORK_ERROR: {name}"), answer.diagnostics)
                self.assertIsNone(answer.work)
                self.assertIsNone(answer.provenance["response_sha256"])
                self.assertIs(answer.provenance["live_refresh_performed"], True)
                self.assertEqual(answer.provenance["retrieved_at"], FIXED_TIME)

    def test_any_non_2xx_status_is_source_unavailable_even_404(self) -> None:
        for code in (404, 410, 503):
            with self.subTest(code=code):
                error = urllib.error.HTTPError(live_adapter.request_url(self.DOI), code, "synthetic", {}, io.BytesIO())
                answer = live_adapter.resolve(self.DOI, live_policy(ScriptedOpener(error)))
                self.assertEqual((answer.state, answer.http_status), (ResolverState.SOURCE_UNAVAILABLE, code))
                self.assertEqual(answer.diagnostics, (f"HTTP_STATUS: {code}",))
        for code in (302, 404, 500):  # an opener that returns, rather than raises, a non-2xx status
            with self.subTest(returned=code):
                response = FakeResponse(json.dumps(csl(self.DOI)).encode(), code, status_attribute=False)
                answer = live_adapter.resolve(self.DOI, live_policy(ScriptedOpener(response)))
                self.assertEqual(answer.state, ResolverState.SOURCE_UNAVAILABLE)
                self.assertTrue(response.closed)

    def test_a_usable_answer_keeps_only_minimum_metadata(self) -> None:
        body = json.dumps(csl(self.DOI)).encode("utf-8")
        response = FakeResponse(body)
        opener = ScriptedOpener(response)
        policy = NetworkPolicy(live=True, opener=opener, timeout_seconds=10, user_agent="synthetic-agent/1")
        answer = live_adapter.resolve(self.DOI, policy)
        self.assertEqual((answer.state, answer.http_status), (ResolverState.DOI_RESOLVED, 200))
        self.assertEqual(answer.work.title, "Calibrating invented sensors on a fictional plateau")
        self.assertEqual([item.display() for item in answer.work.authors], ["Alphatest, Ada", "Gammatest"])
        self.assertEqual((answer.work.year, answer.work.issue), ("2031", "3"))
        self.assertEqual(answer.provenance["response_sha256"], sha256_bytes(body))
        self.assertIsNone(answer.body)
        self.assertNotIn("abstract", json.dumps(answer.to_dict()))
        (request, timeout), = opener.calls
        self.assertEqual(timeout, 10)
        self.assertEqual(request.full_url, "https://doi.org/10.5555/sgate.test.0001")
        self.assertEqual(request.get_header("User-agent"), "synthetic-agent/1")
        self.assertEqual(request.get_header("Accept"), live_adapter.ACCEPT)
        self.assertTrue(response.closed)

    def test_the_body_is_kept_only_when_the_caller_allows_it(self) -> None:
        body = json.dumps(csl(self.DOI)).encode("utf-8")
        answer = live_adapter.resolve(self.DOI, live_policy(ScriptedOpener(FakeResponse(body))), keep_body=True)
        self.assertEqual(answer.body, body.decode("utf-8"))
        self.assertEqual(answer.to_dict()["body"], body.decode("utf-8"))

    def test_unusable_bodies_are_source_unavailable_with_their_digest(self) -> None:
        for label, body in (
            ("not JSON", b"<html>synthetic</html>"),
            ("not an object", b"[1, 2]"),
            ("no title", json.dumps(csl(self.DOI, title=[])).encode()),
            ("no DOI", json.dumps({**csl(self.DOI), "DOI": None}).encode()),
            ("no authors", json.dumps({**csl(self.DOI), "author": None}).encode()),
            ("an author without a name", json.dumps({**csl(self.DOI), "author": [{"given": "Ada"}]}).encode()),
        ):
            with self.subTest(body=label):
                answer = live_adapter.resolve(self.DOI, live_policy(ScriptedOpener(FakeResponse(body))))
                self.assertEqual(answer.state, ResolverState.SOURCE_UNAVAILABLE)
                self.assertTrue(answer.diagnostics[0].startswith("RESPONSE_UNUSABLE"), answer.diagnostics)
                self.assertEqual(answer.provenance["response_sha256"], sha256_bytes(body))

    def test_an_oversized_body_is_refused_unhashed(self) -> None:
        body = b" " * (live_adapter.MAX_RESPONSE_BYTES + 5)
        answer = live_adapter.resolve(self.DOI, live_policy(ScriptedOpener(FakeResponse(body))))
        self.assertEqual(answer.state, ResolverState.SOURCE_UNAVAILABLE)
        self.assertTrue(answer.diagnostics[0].startswith("RESPONSE_TOO_LARGE"))
        self.assertIsNone(answer.provenance["response_sha256"])

    def test_a_live_answer_for_another_work_is_a_target_mismatch(self) -> None:
        body = json.dumps(csl("10.5555/sgate.test.0004")).encode()
        answer = live_adapter.resolve(self.DOI, live_policy(ScriptedOpener(FakeResponse(body))))
        self.assertEqual(answer.state, ResolverState.DOI_TARGET_MISMATCH)
        self.assertEqual(answer.work.doi, "10.5555/sgate.test.0004")

    def test_request_urls_percent_encode_the_suffix(self) -> None:
        self.assertEqual(live_adapter.request_url("10.5555/a b<c>#?"), "https://doi.org/10.5555/a%20b%3Cc%3E%23%3F")


# ---------------------------------------------------------------------------
# Checks, through the real engine
# ---------------------------------------------------------------------------

_DEFAULT: Any = object()


class CitationProjectCase(TempDirTestCase):
    """A synthetic project with one observations input and the three citation checks.

    By default all three citations resolve and match, and the log backs each
    claim, so the run is a PASS and each test introduces exactly one defect.
    The default opener refuses and records any call, so a test that expects
    no network access can assert it.
    """

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop(HMAC_KEY_FILE_ENV, None)
        self.root = self.tmp / "project"
        self.write("project/data/observations.csv", OBSERVATIONS)
        self.opener = failing_opener()

    def build(
        self,
        *,
        cited: Any = _DEFAULT,
        frozen: Any = _DEFAULT,
        log: Any = _DEFAULT,
        kinds: tuple[str, ...] = CITATION_KINDS,
        live: bool = False,
        permissions: dict[str, bool] | None = None,
        check_changes: dict[str, Any] | None = None,
    ) -> Path:
        """Write the project. ``None`` leaves a document undeclared; a string is written verbatim."""
        documents = {
            "entries": entries_document(cite("C1", WORK_A), cite("C2", WORK_B), cite("C3", WORK_C))
            if cited is _DEFAULT
            else cited,
            "frozen": frozen_document(found(WORK_A["doi"]), found(WORK_B["doi"]), found(WORK_C["doi"]))
            if frozen is _DEFAULT
            else frozen,
            "log": good_log() if log is _DEFAULT else log,
        }
        declared: dict[str, Any] = {"live": live}
        for name, document in documents.items():
            if document is None:
                continue
            relpath = f"citations/{name}.json"
            declared[name] = relpath
            self.write(f"project/{relpath}", document if isinstance(document, str) else json.dumps(document))
        checks = [{"id": "rows", "kind": "row_count", "version": "1", "inputs": ["observations"]}]
        checks += [{"id": kind, "kind": kind, "version": "1", **(check_changes or {})} for kind in kinds]
        manifest = {
            "schema": "science-gate-manifest/v1",
            "inputs": [
                {
                    "id": "observations",
                    "path": "data/observations.csv",
                    "format": "csv",
                    "expected_rows": 2,
                    "denominator_source": "INDEPENDENT",
                }
            ],
            "checks": checks,
            "citations": declared,
            "corpus": {"access_class": "SYNTHETIC", "permissions": permissions or {}},
        }
        return self.write_manifest(manifest, "project/manifest.json")

    def run_project(self, *, live: bool = False, opener: Any = None, **build: Any) -> VerificationRun:
        path = self.build(**build)
        return verify(path, live=live, network=NetworkPolicy(opener=opener or self.opener))

    def check(self, run: VerificationRun, kind: str) -> Any:
        (found_result,) = [item for item in run.result.checks if item.check_id == kind]
        return found_result

    def invariant(self, run: VerificationRun, name: str) -> Any:
        (result,) = [item for item in run.result.invariants if item.name == name]
        return result

    def assertOutcome(self, result: Any, verdict: Status, reason: Reason, *modes: FailureMode) -> None:
        self.assertEqual((result.verdict, result.reason), (verdict, reason), result.diagnostics)
        for mode in modes:
            self.assertIn(mode, result.failure_modes)


class CleanProjectTests(CitationProjectCase):
    def test_a_clean_project_passes_with_evidence_from_every_layer(self) -> None:
        run = self.run_project()
        self.assertEqual((run.status, run.exit_code), (Status.PASS, 0), [item.detail for item in run.findings])
        for kind in CITATION_KINDS:
            with self.subTest(kind=kind):
                result = self.check(run, kind)
                self.assertEqual((result.execution_state, result.verdict), (ExecutionState.CHECKED, Status.PASS))
                self.assertEqual(result.rows_examined, 3)
                self.assertIsNotNone(result.invocation_id)
        self.assertEqual(self.opener.calls, [])
        claims = self.invariant(run, "checked_claims_le_invocations")
        self.assertTrue(claims.holds)
        expected = "verification_log: claimed_verified vs complete invocation records: 3 claimed <= 3"
        self.assertIn(expected, claims.detail)

    def test_resolver_evidence_carries_every_provenance_field(self) -> None:
        evidence = self.check(self.run_project(), "citation_resolver").evidence
        self.assertEqual(evidence["state_totals"], {"DOI_RESOLVED": 3, "DOI_NOT_RESOLVED_AT_CAPTURE": 0,
                                                    "DOI_TARGET_MISMATCH": 0, "SOURCE_UNAVAILABLE": 0})
        for item in evidence["resolutions"]:
            self.assertEqual(set(item["provenance"]), set(PROVENANCE_FIELDS))
            self.assertTrue(all(value is not None for value in item["provenance"].values()))
        self.assertEqual(evidence["network"]["live"], False)

    def test_log_evidence_names_the_invocation_behind_each_claim(self) -> None:
        evidence = self.check(self.run_project(), "verification_log").evidence
        self.assertEqual(
            evidence["backed"],
            [{"citation_id": f"C{i}", "invocation_ids": [f"inv-{i}"]} for i in (1, 2, 3)],
        )
        self.assertEqual(evidence["coverage"]["state"], "ASSESSED")
        self.assertEqual(evidence["invocation_records"]["complete"], 3)

    def test_the_checks_take_no_inputs_or_params(self) -> None:
        cases = (({"inputs": ["observations"]}, "UNEXPECTED_INPUTS"), ({"params": {"strict": True}}, "UNKNOWN_PARAM"))
        for changes, code in cases:
            with self.subTest(changes=changes):
                run = self.run_project(check_changes=changes)
                for kind in CITATION_KINDS:
                    result = self.check(run, kind)
                    self.assertEqual(result.verdict, Status.ERROR)
                    self.assertIn(code, result.diagnostics[0])
                self.assertEqual(run.status, Status.ERROR)


class VerificationLogTests(CitationProjectCase):
    def run_log(self, log: Any, **build: Any) -> tuple[VerificationRun, Any]:
        run = self.run_project(log=log, kinds=("verification_log",), **build)
        return run, self.check(run, "verification_log")

    def test_eight_claimed_verifications_with_zero_invocations_abstain_unverified(self) -> None:
        ids = [f"C{index}" for index in range(1, 9)]
        run, result = self.run_log(log_document([(cid, "VERIFIED") for cid in ids], []), frozen=None, cited=None)
        self.assertOutcome(result, Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.NARRATED_VERIFICATION)
        self.assertEqual(result.evidence["narrated"], ids)
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.UNVERIFIED, 2))
        claims = self.invariant(run, "checked_claims_le_invocations")
        self.assertTrue(claims.violated)
        self.assertIn("claimed_verified vs complete invocation records: 8 claimed but only 0 invoked", claims.detail)

    def test_a_log_without_an_invocation_list_is_unknown_not_zero(self) -> None:
        run, result = self.run_log(log_document([("C1", "VERIFIED"), ("C2", "VERIFIED"), ("C3", "VERIFIED")], None))
        self.assertOutcome(result, Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.NARRATED_VERIFICATION)
        records = result.evidence["invocation_records"]
        self.assertEqual((records["state"], records["total"], records["complete"]), ("NOT_RECORDED", None, None))
        detail = self.invariant(run, "checked_claims_le_invocations").detail
        self.assertIn("3 claimed with no invocation record", detail)

    def test_an_incomplete_invocation_backs_nothing(self) -> None:
        invocations = [
            invocation("inv-1", "C1"),
            invocation("inv-2", "C2", response_sha256=None),
            invocation("inv-3", "C3", retrieved_at="yesterday"),
        ]
        log = log_document([("C1", "VERIFIED"), ("C2", "VERIFIED"), ("C3", "VERIFIED")], invocations)
        _, result = self.run_log(log)
        self.assertOutcome(result, Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.NARRATED_VERIFICATION)
        self.assertEqual(result.evidence["narrated"], ["C2", "C3"])
        incomplete = result.evidence["invocation_records"]["incomplete"]
        self.assertEqual(
            {item["invocation_id"]: item["problems"] for item in incomplete},
            {"inv-2": ["MISSING_FIELD: response_sha256"], "inv-3": ["INVALID_FIELD: retrieved_at"]},
        )

    def test_an_invocation_for_another_citation_backs_nothing(self) -> None:
        invocations = [invocation("inv-1", "C1"), invocation("inv-2", "C1"), invocation("inv-3", "C9")]
        log = log_document([("C1", "VERIFIED"), ("C2", "VERIFIED"), ("C3", "VERIFIED")], invocations)
        _, result = self.run_log(log)
        self.assertEqual(result.evidence["narrated"], ["C2", "C3"])
        self.assertEqual(result.evidence["invocation_records"]["without_log_entry"], ["inv-3"])

    def test_a_headline_count_above_the_itemized_claims_is_narrated(self) -> None:
        run, result = self.run_log(log_document([(f"C{i}", "VERIFIED") for i in (1, 2, 3)],
                                                [invocation(f"inv-{i}", f"C{i}") for i in (1, 2, 3)], claimed=5))
        self.assertOutcome(result, Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.NARRATED_VERIFICATION)
        self.assertIn("claimed_verified=5 but only 3", result.diagnostics[0])
        self.assertTrue(self.invariant(run, "checked_claims_le_invocations").violated)

    def test_a_headline_count_below_the_itemized_claims_is_an_inconsistent_log(self) -> None:
        _, result = self.run_log(log_document([(f"C{i}", "VERIFIED") for i in (1, 2, 3)],
                                              [invocation(f"inv-{i}", f"C{i}") for i in (1, 2, 3)], claimed=2))
        self.assertOutcome(result, Status.ABSTAIN, Reason.PROTOCOL_BROKEN, FailureMode.DEFECTIVE_VERIFICATION)

    def test_a_citation_the_log_does_not_claim_is_unverified_but_not_narrated(self) -> None:
        log = log_document([("C1", "VERIFIED"), ("C2", "VERIFIED"), ("C3", "NOT_VERIFIED")],
                           [invocation("inv-1", "C1"), invocation("inv-2", "C2")])
        run, result = self.run_log(log)
        self.assertOutcome(result, Status.ABSTAIN, Reason.UNVERIFIED)
        self.assertNotIn(FailureMode.NARRATED_VERIFICATION, result.failure_modes)
        self.assertEqual(result.evidence["not_claimed"], ["C3"])
        self.assertTrue(self.invariant(run, "checked_claims_le_invocations").holds)

    def test_coverage_against_the_bibliography(self) -> None:
        _, result = self.run_log(good_log("C1", "C2"))
        self.assertOutcome(result, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE, FailureMode.OMITTED_POPULATION)
        self.assertEqual(result.evidence["coverage"]["not_in_log"], ["C3"])

        _, result = self.run_log(good_log("C1", "C2", "C3", "C4"))
        self.assertOutcome(result, Status.ABSTAIN, Reason.PROTOCOL_BROKEN, FailureMode.PROTOCOL_DRIFT)
        self.assertEqual(result.evidence["coverage"]["unknown"], ["C4"])

    def test_coverage_is_not_assessed_without_a_bibliography_and_unavailable_with_a_broken_one(self) -> None:
        _, result = self.run_log(good_log(), cited=None)
        self.assertEqual(result.verdict, Status.PASS)
        self.assertEqual(result.evidence["coverage"]["state"], "NOT_ASSESSED")

        _, result = self.run_log(good_log(), cited="{broken")
        self.assertOutcome(result, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE)
        self.assertEqual(result.evidence["coverage"]["state"], "UNAVAILABLE")

    def test_nothing_to_examine_is_never_pass(self) -> None:
        cases = {
            "undeclared": (None, ExecutionState.NOT_APPLICABLE, Reason.OUT_OF_SCOPE),
            "empty log": (log_document([], []), ExecutionState.NOT_APPLICABLE, Reason.INSUFFICIENT_EVIDENCE),
            "empty file": ("", ExecutionState.SKIPPED, Reason.INSUFFICIENT_EVIDENCE),
            "broken JSON": ("{broken", ExecutionState.SKIPPED, Reason.PROTOCOL_BROKEN),
        }
        for label, (log, state, reason) in cases.items():
            with self.subTest(case=label):
                run, result = self.run_log(log)
                outcome = (result.execution_state, result.verdict, result.reason)
                self.assertEqual(outcome, (state, Status.ABSTAIN, reason))
                self.assertNotEqual(run.status, Status.PASS)

    def test_malformed_logs_are_protocol_broken(self) -> None:
        good = good_log()
        for label, change in {
            "unknown status": {"entries": [{"citation_id": "C1", "claimed_status": "PROBABLY"}]},
            "duplicate entry": {"entries": good["entries"] + good["entries"][:1]},
            "duplicate invocation id": {"invocations": good["invocations"] + good["invocations"][:1]},
            "negative claim count": {"claimed_verified": -1},
            "boolean claim count": {"claimed_verified": True},
            "no verifier": {"verifier": None},
            "verifier without version": {"verifier": {"name": "synthetic"}},
            "unknown key": {"notes": "synthetic"},
            "other schema": {"schema": "other/v1"},
            "invocation without citation": {"invocations": [{"invocation_id": "inv-1"}]},
        }.items():
            with self.subTest(case=label):
                _, result = self.run_log({**good, **change})
                outcome = (result.execution_state, result.reason)
                self.assertEqual(outcome, (ExecutionState.SKIPPED, Reason.PROTOCOL_BROKEN))
                self.assertIn("MALFORMED_DOCUMENT", result.diagnostics[0])


class ResolverTests(CitationProjectCase):
    def run_resolver(self, **build: Any) -> tuple[VerificationRun, Any]:
        run = self.run_project(kinds=("citation_resolver",), **build)
        return run, self.check(run, "citation_resolver")

    def test_a_record_missing_provenance_is_source_unavailable(self) -> None:
        incomplete = {key: value for key, value in found(WORK_B["doi"]).items() if key != "resolver_identity"}
        run, result = self.run_resolver(frozen=frozen_document(found(WORK_A["doi"]), incomplete, found(WORK_C["doi"])))
        self.assertOutcome(result, Status.ABSTAIN, Reason.SOURCE_UNAVAILABLE)
        self.assertIn("MISSING_PROVENANCE: resolver_identity", result.diagnostics[0])
        self.assertEqual(result.evidence["state_totals"]["SOURCE_UNAVAILABLE"], 1)
        self.assertEqual(run.result.reason, Reason.SOURCE_UNAVAILABLE)

    def test_a_doi_missing_from_the_frozen_set_is_never_reported_as_not_found(self) -> None:
        _, result = self.run_resolver(frozen=frozen_document(found(WORK_A["doi"]), found(WORK_B["doi"])))
        self.assertOutcome(result, Status.ABSTAIN, Reason.SOURCE_UNAVAILABLE)
        states = {item["doi"]: item["state"] for item in result.evidence["resolutions"]}
        self.assertEqual(states[WORK_C["doi"]], "SOURCE_UNAVAILABLE")
        self.assertEqual(result.evidence["state_totals"]["DOI_NOT_RESOLVED_AT_CAPTURE"], 0)
        self.assertEqual(self.opener.calls, [], "live access is off, so the opener must not be called")

    def test_without_a_usable_frozen_set_every_doi_is_source_unavailable(self) -> None:
        for frozen, marker in ((None, "NO_FROZEN_SET"), ("", "FROZEN_SET_UNAVAILABLE")):
            with self.subTest(marker=marker):
                _, result = self.run_resolver(frozen=frozen)
                self.assertOutcome(result, Status.ABSTAIN, Reason.SOURCE_UNAVAILABLE)
                self.assertEqual(result.evidence["state_totals"]["SOURCE_UNAVAILABLE"], 3)
                self.assertIn(marker, result.diagnostics[0])

    def test_a_malformed_frozen_set_is_protocol_broken(self) -> None:
        _, result = self.run_resolver(frozen=frozen_document(found(WORK_A["doi"]), found(WORK_A["doi"])))
        self.assertEqual((result.execution_state, result.reason), (ExecutionState.SKIPPED, Reason.PROTOCOL_BROKEN))

    def test_not_found_and_target_mismatch_fail(self) -> None:
        run, result = self.run_resolver(
            frozen=frozen_document(found(WORK_A["doi"], WORK_D), found(WORK_B["doi"]), not_found(WORK_C["doi"]))
        )
        self.assertOutcome(result, Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.SOURCE_MISMATCH)
        self.assertEqual(
            {item["doi"]: item["state"] for item in result.evidence["resolutions"]},
            {
                WORK_A["doi"]: "DOI_TARGET_MISMATCH",
                WORK_B["doi"]: "DOI_RESOLVED",
                WORK_C["doi"]: "DOI_NOT_RESOLVED_AT_CAPTURE",
            },
        )
        self.assertEqual((run.status, run.exit_code), (Status.FAIL, 1))

    def test_a_doi_cited_twice_is_resolved_once(self) -> None:
        cited = entries_document(cite("C1", WORK_A), cite("C2", WORK_A, doi="https://doi.org/10.5555/SGATE.TEST.0001"))
        _, result = self.run_resolver(cited=cited, log=good_log("C1", "C2"))
        self.assertEqual(result.verdict, Status.PASS)
        self.assertEqual(result.evidence["dois_examined"], 1)
        self.assertEqual(result.evidence["resolutions"][0]["citation_ids"], ["C1", "C2"])
        self.assertEqual(result.rows_examined, 2)

    def test_citation_documents_that_cannot_be_used(self) -> None:
        skipped, broken = ExecutionState.SKIPPED, Reason.PROTOCOL_BROKEN
        cases = {
            "undeclared": (None, ExecutionState.NOT_APPLICABLE, Reason.OUT_OF_SCOPE),
            "no citations": (entries_document(), ExecutionState.NOT_APPLICABLE, Reason.INSUFFICIENT_EVIDENCE),
            "invalid DOI": (entries_document(cite("C1", WORK_A, doi="10.5555")), skipped, broken),
            "duplicate id": (entries_document(cite("C1", WORK_A), cite("C1", WORK_B)), skipped, broken),
            "bad id": (entries_document(cite("C 1", WORK_A)), skipped, broken),
            "empty file": ("", ExecutionState.SKIPPED, Reason.INSUFFICIENT_EVIDENCE),
        }
        for label, (cited, state, reason) in cases.items():
            with self.subTest(case=label):
                _, result = self.run_resolver(cited=cited)
                outcome = (result.execution_state, result.verdict, result.reason)
                self.assertEqual(outcome, (state, Status.ABSTAIN, reason))


def partial_frozen() -> dict[str, Any]:
    """A frozen set that captured the first two citations but not the third."""
    return frozen_document(found(WORK_A["doi"]), found(WORK_B["doi"]))


class LiveResolutionTests(CitationProjectCase):
    """Live access only fills gaps in the frozen set, and only when enabled (requirement 17)."""

    def test_network_failure_becomes_source_unavailable(self) -> None:
        opener = failing_opener()
        run = self.run_project(frozen=partial_frozen(), live=True, opener=opener)
        for kind in ("citation_resolver", "citation_metadata"):
            with self.subTest(kind=kind):
                self.assertOutcome(self.check(run, kind), Status.ABSTAIN, Reason.SOURCE_UNAVAILABLE)
        resolution = self.check(run, "citation_resolver").evidence["resolutions"][2]
        self.assertEqual((resolution["state"], resolution["source"]), ("SOURCE_UNAVAILABLE", "live"))
        self.assertTrue(resolution["diagnostics"][0].startswith("NOT_IN_FROZEN_SET"))
        self.assertTrue(resolution["diagnostics"][1].startswith("NETWORK_ERROR: OSError"))
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.SOURCE_UNAVAILABLE, 2))
        # Only the DOI missing from the capture was looked up, once, for both layers.
        self.assertEqual([request.full_url for request, _ in opener.calls], [live_adapter.request_url(WORK_C["doi"])])

    def test_the_manifest_switch_also_enables_live_access(self) -> None:
        opener = failing_opener()
        self.build(frozen=partial_frozen(), live=True)
        run = verify(self.root / "manifest.json", network=NetworkPolicy(opener=opener))
        self.assertTrue(run.network.live)
        self.assertEqual(len(opener.calls), 1)

    def test_each_run_asks_again(self) -> None:
        opener = failing_opener()
        self.run_project(frozen=partial_frozen(), live=True, opener=opener)
        self.run_project(frozen=partial_frozen(), live=True, opener=opener)
        self.assertEqual(len(opener.calls), 2)

    def test_a_usable_live_answer_completes_the_run(self) -> None:
        body = json.dumps(
            csl(WORK_C["doi"], title=WORK_C["title"], author=[{"family": "Deltatest", "given": "Dee"}],
                issued={"date-parts": [[2030]]}, **{"container-title": WORK_C["journal"], "volume": "7", "issue": "2"})
        ).encode("utf-8")
        opener = ScriptedOpener(FakeResponse(body))
        run = self.run_project(frozen=partial_frozen(), live=True, opener=opener)
        self.assertEqual(run.status, Status.PASS, [item.detail for item in run.findings])
        resolution = self.check(run, "citation_resolver").evidence["resolutions"][2]
        self.assertEqual((resolution["source"], resolution["provenance"]["live_refresh_performed"]), ("live", True))
        self.assertNotIn("body", resolution, "redistribution is not allowed by default")
        self.assertEqual(self.check(run, "citation_metadata").evidence["citations"][2]["reference"]["source"], "live")

    def test_the_body_is_recorded_only_when_redistribution_is_allowed(self) -> None:
        body = json.dumps(csl(WORK_C["doi"])).encode("utf-8")
        run = self.run_project(frozen=partial_frozen(), live=True, opener=ScriptedOpener(FakeResponse(body)),
                               permissions={"redistribution_allowed": True})
        resolution = self.check(run, "citation_resolver").evidence["resolutions"][2]
        self.assertEqual(resolution["body"], body.decode("utf-8"))

    def test_a_usable_frozen_record_is_never_replaced_by_a_live_lookup(self) -> None:
        opener = failing_opener()
        run = self.run_project(live=True, opener=opener)
        self.assertEqual(run.status, Status.PASS)
        self.assertEqual(opener.calls, [])


class MetadataTests(CitationProjectCase):
    def assess(self, *cited: dict[str, Any], frozen: Any = _DEFAULT) -> tuple[Any, dict[str, dict[str, Any]]]:
        run = self.run_project(cited=entries_document(*cited), frozen=frozen, kinds=("citation_metadata",))
        result = self.check(run, "citation_metadata")
        return result, {item["citation_id"]: item for item in result.evidence["citations"]}

    def test_titles_compare_after_case_punctuation_and_whitespace_normalization(self) -> None:
        title = "  CALIBRATING invented-sensors on a fictional plateau!"
        cited = cite("C1", WORK_A, title=title, journal="synthetic fixture letters.")
        result, by_id = self.assess(cited)
        self.assertEqual(result.verdict, Status.PASS)
        self.assertEqual(by_id["C1"]["primary_disposition"], "VERIFIED_WITHIN_DECLARED_SCOPE")
        self.assertEqual(normalize_text("Grid-Free  Methods."), "grid free methods")
        self.assertNotEqual(normalize_text("Grid-Free Methods"), normalize_text("Grid-Bound Methods"))

    def test_wrong_author_is_a_field_mismatch(self) -> None:
        result, by_id = self.assess(cite("C2", WORK_B, authors=[author("Betatest", "Bo"), author("Omegatest", "Oz")]))
        self.assertOutcome(result, Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.SOURCE_MISMATCH)
        outcome = (by_id["C2"]["primary_disposition"], by_id["C2"]["defects"])
        self.assertEqual(outcome, ("FIELD_MISMATCH", ["AUTHOR_MISMATCH"]))
        self.assertEqual(by_id["C2"]["fields"]["authors"]["cited"], ["Betatest, Bo", "Omegatest, Oz"])

    def test_author_order_is_its_own_defect(self) -> None:
        _, by_id = self.assess(cite("C2", WORK_B, authors=list(reversed(WORK_B["authors"]))))
        self.assertEqual(by_id["C2"]["defects"], ["AUTHOR_ORDER_MISMATCH"])

    def test_given_names_compare_by_initial_when_abbreviated(self) -> None:
        cases = {
            "initial": ([author("Alphatest", "A."), author("Gammatest", "C")], []),
            "omitted": ([author("Alphatest"), author("Gammatest", None)], []),
            "different initial": ([author("Alphatest", "B."), author("Gammatest", "Cy")], ["AUTHOR_MISMATCH"]),
            "different name": ([author("Alphatest", "Ava"), author("Gammatest", "Cy")], ["AUTHOR_MISMATCH"]),
        }
        for label, (authors, defects) in cases.items():
            with self.subTest(case=label):
                _, by_id = self.assess(cite("C1", WORK_A, authors=authors))
                self.assertEqual(by_id["C1"]["defects"], defects)

    def test_defects_overlap_and_totals_are_per_defect_type(self) -> None:
        both = cite("C1", WORK_A, year=2029, journal="Invented Methods Quarterly", authors=[author("Alphatest", "Ada")])
        year_only = cite("C2", WORK_B, year=2020)
        result, by_id = self.assess(both, year_only, cite("C3", WORK_C))
        self.assertEqual(by_id["C1"]["defects"], ["AUTHOR_MISMATCH", "YEAR_MISMATCH", "JOURNAL_MISMATCH"])
        evidence = result.evidence
        self.assertEqual(evidence["defect_totals"]["YEAR_MISMATCH"], 2)
        self.assertEqual(evidence["defect_totals"]["AUTHOR_MISMATCH"], 1)
        self.assertEqual(set(evidence["defect_totals"]), {defect.value for defect in Defect})
        self.assertEqual(sum(evidence["defect_totals"].values()), 4, "totals count defects, not citations")
        self.assertEqual(evidence["disposition_totals"]["FIELD_MISMATCH"], 2)
        self.assertEqual(sum(evidence["disposition_totals"].values()), 3, "each citation has exactly one disposition")
        self.assertEqual(set(evidence["disposition_totals"]), set(DISPOSITIONS))

    def test_fields_absent_on_either_side_are_not_compared(self) -> None:
        cited = {key: value for key, value in cite("C1", WORK_A).items() if key not in ("issue", "volume")}
        without_journal = found(WORK_A["doi"], {**WORK_A, "journal": None})
        frozen = frozen_document(without_journal, found(WORK_B["doi"]), found(WORK_C["doi"]))
        result, by_id = self.assess(cited, frozen=frozen)
        self.assertEqual(result.verdict, Status.PASS)
        self.assertEqual(by_id["C1"]["fields_not_compared"], ["issue", "journal", "volume"])
        self.assertEqual(by_id["C1"]["fields"]["journal"], {"outcome": "NOT_IN_RECORD"})
        self.assertEqual(by_id["C1"]["fields"]["issue"], {"outcome": "NOT_CITED"})

    def test_fields_taken_from_two_works_are_a_conflated_entry(self) -> None:
        conflated = cite("C2", WORK_B, title=WORK_C["title"])
        result, by_id = self.assess(cite("C1", WORK_A), conflated, cite("C3", WORK_C))
        self.assertOutcome(result, Status.FAIL, Reason.SOURCE_MISMATCH)
        item = by_id["C2"]
        self.assertEqual(item["primary_disposition"], "CONFLATED_ENTRY")
        self.assertEqual(item["defects"], ["TITLE_MISMATCH", "CONFLATED_ENTRY"])
        self.assertEqual(
            item["conflation"], {"doi": [WORK_B["doi"]], "title": [WORK_C["doi"]], "authors": [WORK_B["doi"]]}
        )

    def test_a_shared_author_team_is_not_conflation(self) -> None:
        same_team = {**WORK_C, "authors": copy.deepcopy(WORK_A["authors"])}
        frozen = frozen_document(found(WORK_A["doi"]), found(WORK_B["doi"]), found(WORK_C["doi"], same_team))
        result, by_id = self.assess(cite("C1", WORK_A), cite("C3", same_team), frozen=frozen)
        self.assertEqual(result.verdict, Status.PASS)
        self.assertIsNone(by_id["C1"]["conflation"])

    def test_a_replacement_candidate_is_never_ground_truth(self) -> None:
        missing = "10.5555/sgate.test.9999"
        frozen = frozen_document(found(WORK_A["doi"]), not_found(missing), found(WORK_C["doi"]))
        result, by_id = self.assess(cite("C1", WORK_A), cite("C3", WORK_C, doi=missing), frozen=frozen)
        self.assertOutcome(result, Status.ABSTAIN, Reason.INSUFFICIENT_EVIDENCE)
        item = by_id["C3"]
        self.assertEqual(item["primary_disposition"], "RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES")
        self.assertIsNone(item["reference"])
        self.assertEqual((item["fields"], item["defects"]), ({}, []))
        candidates = [{"doi": WORK_C["doi"], "matched_fields": ["title", "authors"]}]
        self.assertEqual(item["replacement_candidates"], candidates)
        self.assertEqual(result.evidence["not_compared"], ["C3"])

    def test_an_unresolved_record_is_neither_reference_nor_candidate(self) -> None:
        incomplete = {key: value for key, value in found(WORK_B["doi"]).items() if key != "response_sha256"}
        frozen = frozen_document(found(WORK_A["doi"]), incomplete)
        result, by_id = self.assess(cite("C1", WORK_A), cite("C2", WORK_B), frozen=frozen)
        self.assertOutcome(result, Status.ABSTAIN, Reason.SOURCE_UNAVAILABLE)
        item = by_id["C2"]
        self.assertEqual((item["primary_disposition"], item["reference"]), ("SOURCE_UNAVAILABLE", None))
        self.assertNotIn("replacement_candidates", item)
        self.assertEqual(result.evidence["reference_pool"], [WORK_A["doi"]])

    def test_a_target_mismatch_is_compared_with_the_work_the_doi_reached(self) -> None:
        frozen = frozen_document(found(WORK_A["doi"], WORK_D), found(WORK_B["doi"]), found(WORK_C["doi"]))
        result, by_id = self.assess(cite("C1", WORK_A), frozen=frozen)
        item = by_id["C1"]
        self.assertEqual((item["resolver_state"], item["reference"]["doi"]), ("DOI_TARGET_MISMATCH", WORK_D["doi"]))
        self.assertEqual(item["primary_disposition"], "FIELD_MISMATCH")
        self.assertIn("DOI_WORK_MISMATCH", item["defects"])
        self.assertIn("TITLE_MISMATCH", item["defects"])


# ---------------------------------------------------------------------------
# Committed fixtures
# ---------------------------------------------------------------------------


class FixtureTests(TempDirTestCase):
    """The committed synthetic fixtures give their documented results, offline (requirement 16)."""

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        block_sockets(self)
        self.opener = failing_opener()

    def verify_fixture(self, name: str, **kwargs: Any) -> VerificationRun:
        kwargs.setdefault("network", NetworkPolicy(opener=self.opener))
        return verify(FIXTURES / name / "manifest.json", **kwargs)

    def expected(self, name: str) -> dict[str, Any]:
        return strict_loads((FIXTURES / name / "expected.json").read_bytes())

    def test_every_fixture_directory_is_covered(self) -> None:
        present = tuple(sorted(path.name for path in FIXTURES.iterdir() if path.is_dir()))
        self.assertEqual(present, FIXTURE_NAMES)

    def test_each_fixture_gives_its_expected_result_offline(self) -> None:
        for name in FIXTURE_NAMES:
            with self.subTest(fixture=name):
                expected, run = self.expected(name), self.verify_fixture(name)
                self.assertEqual(
                    (run.status.value, run.result.reason.value, run.exit_code),
                    (expected["status"], expected["reason"], expected["exit_code"]),
                    [item.detail for item in run.findings],
                )
                self.assertEqual({item.check_id: item.verdict.value for item in run.result.checks}, expected["checks"])
                violated = sorted(item.name for item in run.result.invariants if item.violated)
                self.assertEqual(violated, expected.get("violated_invariants", []))
                self.assert_details(run, expected)
        self.assertEqual(self.opener.calls, [])

    def assert_details(self, run: VerificationRun, expected: dict[str, Any]) -> None:
        checks = {item.kind: item for item in run.result.checks}
        metadata = {item["citation_id"]: item for item in checks["citation_metadata"].evidence.get("citations", [])}
        states = {item["doi"]: item["state"] for item in checks["citation_resolver"].evidence.get("resolutions", [])}
        for doi, state in expected.get("resolver_states", {}).items():
            self.assertEqual(states[doi], state)
        for citation_id, disposition in expected.get("dispositions", {}).items():
            self.assertEqual(metadata[citation_id]["primary_disposition"], disposition)
        for citation_id, defects in expected.get("defects", {}).items():
            self.assertEqual(metadata[citation_id]["defects"], defects)
        for citation_id, dois in expected.get("replacement_candidates", {}).items():
            self.assertEqual([item["doi"] for item in metadata[citation_id]["replacement_candidates"]], dois)
            self.assertIsNone(metadata[citation_id]["reference"])

    def test_wrong_author_and_nonexistent_doi_work_offline(self) -> None:
        wrong = self.verify_fixture("wrong-author", live=False)
        self.assertEqual((wrong.status, wrong.exit_code), (Status.FAIL, 1))
        item = self.find(wrong, "citation_metadata", "C2")
        self.assertEqual((item["primary_disposition"], item["defects"]), ("FIELD_MISMATCH", ["AUTHOR_MISMATCH"]))

        missing = self.verify_fixture("nonexistent-doi", live=False)
        self.assertEqual((missing.status, missing.exit_code), (Status.FAIL, 1))
        resolver = {item.kind: item for item in missing.result.checks}["citation_resolver"]
        states = {item["doi"]: item["state"] for item in resolver.evidence["resolutions"]}
        self.assertEqual(states["10.5555/sgate.fx.9999"], ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE.value)
        self.assertEqual(self.opener.calls, [])

    def test_eight_claimed_zero_invocations_fixture_abstains_unverified(self) -> None:
        run = self.verify_fixture("narrated-log")
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.UNVERIFIED, 2))
        log = {item.kind: item for item in run.result.checks}["verification_log"]
        self.assertEqual((log.evidence["claimed_verified"], log.evidence["invocation_records"]["total"]), (8, 0))
        self.assertIn(FailureMode.NARRATED_VERIFICATION, run.result.failure_modes)

    def test_missing_from_frozen_fixture_under_a_failing_network(self) -> None:
        opener = failing_opener()
        run = self.verify_fixture("missing-from-frozen", live=True, network=NetworkPolicy(opener=opener))
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.SOURCE_UNAVAILABLE, 2))
        self.assertEqual(len(opener.calls), 1)

    def test_every_fixture_has_one_primary_disposition_per_citation(self) -> None:
        for name in FIXTURE_NAMES:
            with self.subTest(fixture=name):
                metadata = {item.kind: item for item in self.verify_fixture(name).result.checks}["citation_metadata"]
                cited = strict_loads((FIXTURES / name / "citations" / "entries.json").read_bytes())["citations"]
                self.assertEqual(sum(metadata.evidence["disposition_totals"].values()), len(cited))
                for item in metadata.evidence["citations"]:
                    self.assertIn(item["primary_disposition"], DISPOSITIONS)

    def test_fixtures_are_synthetic_and_internally_consistent(self) -> None:
        for name in FIXTURE_NAMES:
            with self.subTest(fixture=name):
                root = FIXTURES / name
                cited = strict_loads((root / "citations" / "entries.json").read_bytes())["citations"]
                records = strict_loads((root / "citations" / "frozen.json").read_bytes())["records"]
                log = strict_loads((root / "citations" / "verification-log.json").read_bytes())
                for doi in [item["doi"] for item in cited] + [item["doi"] for item in records]:
                    self.assertTrue(doi.startswith("10.5555/sgate.fx."), doi)
                for record in records:
                    self.assertTrue(record["request_url_or_query"].startswith("https://resolver.invalid/"))
                captured = {record["doi"]: record["response_sha256"] for record in records}
                by_citation = {item["citation_id"]: item["doi"] for item in cited}
                for item in log["invocations"]:
                    doi = by_citation[item["citation_id"]]
                    if doi in captured:
                        self.assertEqual(item["response_sha256"], captured[doi], item["invocation_id"])

    def find(self, run: VerificationRun, kind: str, citation_id: str) -> dict[str, Any]:
        result = {item.kind: item for item in run.result.checks}[kind]
        (item,) = [entry for entry in result.evidence["citations"] if entry["citation_id"] == citation_id]
        return item


class DeterminismTests(TempDirTestCase):
    def test_cli_output_is_identical_under_different_hash_seeds(self) -> None:
        hidden = (HMAC_KEY_FILE_ENV, "PYTHONHASHSEED")
        environment = {key: value for key, value in os.environ.items() if key not in hidden}
        environment.update(
            {"PYTHONPATH": str(SRC_DIR), "PYTHONDONTWRITEBYTECODE": "1", "SCIENCE_GATE_FIXED_TIME": FIXED_TIME}
        )
        manifest = FIXTURES / "conflated-entry" / "manifest.json"
        outputs: dict[str, dict[str, bytes]] = {}
        for seed in ("0", "4242"):
            out = self.tmp / f"run-{seed}"
            completed = subprocess.run(
                [sys.executable, "-m", "science_gate.cli", "verify", str(manifest), "--output", str(out)],
                cwd=self.tmp,
                env={**environment, "PYTHONHASHSEED": seed},
                capture_output=True,
                text=True,
                timeout=300,
            )
            self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
            outputs[seed] = {path.name: path.read_bytes() for path in sorted(out.iterdir())}
        self.assertEqual(sorted(outputs["0"]), sorted(outputs["4242"]))
        for name in outputs["0"]:
            with self.subTest(file=name):
                self.assertEqual(outputs["0"][name], outputs["4242"][name])


# ---------------------------------------------------------------------------
# Schema documentation
# ---------------------------------------------------------------------------


class CitationSchemaDocumentTests(unittest.TestCase):
    """The JSON Schema is documentation; these tests keep it in step with the code."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = strict_loads((REPO_ROOT / "schemas" / "citations.schema.json").read_bytes())
        cls.defs = cls.schema["$defs"]

    def keys(self, name: str) -> set[str]:
        return set(self.defs[name]["properties"])

    def test_draft(self) -> None:
        self.assertEqual(self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_key_sets_match_the_parsers(self) -> None:
        self.assertEqual(self.keys("entries_document"), set(ENTRIES_KEYS))
        self.assertEqual(self.keys("citation"), set(CITATION_KEYS))
        self.assertEqual(self.keys("work"), set(WORK_KEYS))
        self.assertEqual(set(CITATION_KEYS), {"citation_id", *WORK_KEYS})
        self.assertEqual(self.keys("author"), set(AUTHOR_KEYS))
        self.assertEqual(self.keys("verification_log"), set(LOG_KEYS))
        self.assertEqual(set(self.defs["verification_log"]["required"]), set(LOG_REQUIRED_KEYS))
        self.assertEqual(self.keys("verifier"), set(VERIFIER_KEYS))
        self.assertEqual(self.keys("log_entry"), set(LOG_ENTRY_KEYS))
        self.assertEqual(self.keys("invocation"), set(INVOCATION_KEYS))
        self.assertEqual(self.keys("frozen_set"), set(FROZEN_KEYS))
        self.assertEqual(self.keys("frozen_record"), set(RECORD_KEYS))
        self.assertTrue(set(PROVENANCE_FIELDS) <= self.keys("frozen_record"))
        self.assertFalse(set(PROVENANCE_FIELDS) & set(self.defs["frozen_record"]["required"]),
                         "missing provenance is per record (SOURCE_UNAVAILABLE), not a structural error")
        for name in ("entries_document", "citation", "work", "author", "verification_log", "verifier", "log_entry",
                     "invocation", "frozen_set", "frozen_record"):
            self.assertIs(self.defs[name]["additionalProperties"], False, name)

    def test_constants_and_enumerations_match_the_code(self) -> None:
        self.assertEqual(self.defs["entries_document"]["properties"]["schema"], {"const": ENTRIES_SCHEMA})
        self.assertEqual(self.defs["verification_log"]["properties"]["schema"], {"const": LOG_SCHEMA})
        self.assertEqual(self.defs["frozen_set"]["properties"]["schema"], {"const": FROZEN_SCHEMA})
        self.assertEqual(tuple(self.defs["frozen_record"]["properties"]["outcome"]["enum"]), OUTCOMES)
        self.assertEqual(tuple(self.defs["log_entry"]["properties"]["claimed_status"]["enum"]), CLAIMED_STATUSES)
        self.assertEqual(self.defs["identifier"]["pattern"], "^" + IDENTIFIER_PATTERN.pattern + "$")
        self.assertEqual(
            [state.value for state in MetadataState] + [ResolverState.SOURCE_UNAVAILABLE.value], list(DISPOSITIONS)
        )


if __name__ == "__main__":
    unittest.main()
