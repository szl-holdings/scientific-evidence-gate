"""Acceptance tests for extension #8: resolver negative controls (ARCHITECTURE.md section 17.14).

The brief's four acceptance cases, each with the worked values it names:

* (a) An opener that answers 200 with a body for everything makes the canary
  resolve: FAIL / BLIND_SPOT, and no citation in the run is DOI_RESOLVED.
* (b) A frozen set without a canary for a touched prefix cannot PASS:
  ABSTAIN / BLIND_SPOT.
* (c) A body with ``responseCode`` 200 behind HTTP 200 is not DOI_RESOLVED.
* (d) A record registered 2026-05-01T00:00:00Z with a log ``retrieved_at`` of
  2026-04-01T00:00:00Z gives NARRATED_VERIFICATION with both timestamps in
  evidence.

Plus the rules around them: body codes decide alone, a capture older than
the DOI's registration is SOURCE_UNAVAILABLE, a live canary is asked only
after a live positive, and the resolver's falsifier is rejected by the real
checker. Everything is synthetic (DOIs under 10.5555, resolver URLs under
``.invalid``), and the network is only ever an injected opener.
"""

from __future__ import annotations

import hashlib
import json
import unittest
import urllib.error
import urllib.parse
from typing import Any

from _helpers import TempDirTestCase
from test_citations import (
    ALL_WORKS,
    FIXTURES,
    PREFIX,
    RUN_ID,
    WORK_A,
    WORK_B,
    WORK_C,
    CitationProjectCase,
    FakeResponse,
    ScriptedOpener,
    block_sockets,
    canary_record,
    context_for,
    failing_opener,
    found,
    frozen_document,
    handle_error,
    invocation,
    live_policy,
    log_document,
    not_found,
)

from science_gate._canonical import strict_loads
from science_gate.adapters import doi_handle as handle_adapter
from science_gate.adapters import live as live_adapter
from science_gate.adapters.frozen import canary_check, parse_frozen, resolve
from science_gate.adapters.records import (
    CANARY_LABEL,
    RecordFormatError,
    canary_doi,
    canary_nonce,
    doi_prefix,
    is_canary_doi,
    state_for_handle_code,
)
from science_gate.citations import check_resolver, falsify_resolver
from science_gate.models import FailureMode, Reason, ResolverState, Status
from science_gate.verifier import NetworkPolicy, verify

REGISTERED_AT = "2026-05-01T00:00:00Z"
LOG_RETRIEVED_AT = "2026-04-01T00:00:00Z"
LATER_CAPTURE = "2026-05-02T09:00:00Z"


def csl_for(work: dict[str, Any]) -> dict[str, Any]:
    """A synthetic CSL JSON record that matches ``work`` field for field."""
    return {
        "DOI": work["doi"],
        "title": [work["title"]],
        "author": [dict(item) for item in work["authors"]],
        "issued": {"date-parts": [[work["year"]]]},
        "container-title": work["journal"],
        "volume": work["volume"],
        "issue": work["issue"],
    }


def requested_doi(request: Any) -> str:
    return urllib.parse.unquote(request.full_url[len(live_adapter.RESOLVER_BASE_URL):])


def invented_metadata(request: Any) -> Any:
    """A content-negotiation resolver that answers every DOI, inventing a record for one it does not know."""
    doi = requested_doi(request)
    known = next((item for item in ALL_WORKS if item["doi"] == doi), None)
    work = known or dict(ALL_WORKS[0], doi=doi, title="An invented record for a DOI that does not exist")
    return FakeResponse(json.dumps(csl_for(work)).encode())


def yes_to_everything(request: Any) -> Any:
    """A resolver that answers HTTP 200 with a plausible body for every request, canaries included.

    Metadata requests get a record for the requested DOI; Handle requests
    get body code 1 ("resolved"). Nothing it says can be trusted.
    """
    url = request.full_url
    if url.startswith(handle_adapter.HANDLE_API_URL):
        handle = urllib.parse.unquote(url[len(handle_adapter.HANDLE_API_URL):])
        return FakeResponse(json.dumps({"responseCode": 1, "handle": handle}).encode())
    return invented_metadata(request)


def raises_handle_error(status: int, body: dict[str, Any]) -> Any:
    """An opener answer that raises an HTTP error carrying a Handle body, as urllib does for a 404."""

    def answer(request: Any) -> Any:
        raise handle_error(request, status, body)

    return answer


def metadata_then(handle_body: dict[str, Any], handle_status: int = 200) -> Any:
    """``handle_body`` (behind ``handle_status``) for every Handle request, and metadata for every work.

    For a DOI it does not know (a canary), content negotiation answers 404.
    """

    def answer(request: Any) -> Any:
        if request.full_url.startswith(handle_adapter.HANDLE_API_URL):
            if handle_status >= 400:
                raise handle_error(request, handle_status, handle_body)
            return FakeResponse(json.dumps(handle_body).encode(), handle_status)
        if any(item["doi"] == requested_doi(request) for item in ALL_WORKS):
            return invented_metadata(request)
        raise handle_error(request, 404, {})

    return answer


def handle_urls(opener: ScriptedOpener) -> list[str]:
    urls = [request.full_url for request, _ in opener.calls]
    return [url for url in urls if url.startswith(handle_adapter.HANDLE_API_URL)]


# ---------------------------------------------------------------------------
# Canary DOIs and Handle body codes
# ---------------------------------------------------------------------------


class CanaryDoiTests(unittest.TestCase):
    def test_the_live_nonce_is_the_first_twelve_hex_of_sha256_of_the_run_id(self) -> None:
        expected = hashlib.sha256(RUN_ID.encode("utf-8")).hexdigest()[:12]
        self.assertEqual(canary_nonce(RUN_ID), expected)
        self.assertEqual(canary_doi(PREFIX, expected), f"10.5555/science-gate-canary-{expected}")
        self.assertNotEqual(canary_nonce(RUN_ID), canary_nonce(RUN_ID + "0"), "each run gets its own canary")

    def test_canary_dois_have_one_shape(self) -> None:
        self.assertTrue(is_canary_doi("10.5555/science-gate-canary-0123456789ab"))
        for doi in (
            "10.5555/sgate.fx.0001",
            "10.5555/science-gate-canary-0123456789AB",
            "10.5555/science-gate-canary-0123456789a",
            "10.5555/x/science-gate-canary-0123456789ab",
        ):
            with self.subTest(doi=doi):
                self.assertFalse(is_canary_doi(doi))
        for prefix, nonce in ((PREFIX, "xyz"), (PREFIX, "0123456789AB"), ("10.55", "0123456789ab"), ("x", "0" * 12)):
            with self.subTest(prefix=prefix, nonce=nonce), self.assertRaises(ValueError):
                canary_doi(prefix, nonce)
        self.assertEqual(doi_prefix("10.5555/sgate.fx.0001/extra"), "10.5555")
        self.assertEqual(CANARY_LABEL, "science-gate-canary-")

    def test_body_codes_decide_alone(self) -> None:
        self.assertIs(state_for_handle_code(1), ResolverState.DOI_RESOLVED)
        self.assertIs(state_for_handle_code(100), ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE)
        self.assertIs(state_for_handle_code(200), ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE)
        for code in (0, 2, 101, 102, 300, 402):
            with self.subTest(code=code):
                self.assertIs(state_for_handle_code(code), ResolverState.SOURCE_UNAVAILABLE)


class HandleAdapterTests(TempDirTestCase):
    """``adapters/doi_handle.py``: the body's responseCode is the answer, never the HTTP status."""

    DOI = "10.5555/science-gate-canary-0123456789ab"

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()

    def lookup(self, answer: Any) -> handle_adapter.HandleAnswer:
        return handle_adapter.lookup(self.DOI, live_policy(ScriptedOpener(answer)))

    def test_c_values_not_found_behind_http_200_is_not_resolved(self) -> None:
        answer = self.lookup(FakeResponse(json.dumps({"responseCode": 200, "handle": self.DOI}).encode(), 200))
        self.assertEqual((answer.http_status, answer.handle_response_code), (200, 200))
        self.assertIs(answer.state, ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE)
        self.assertIsNot(answer.state, ResolverState.DOI_RESOLVED)

    def test_the_body_code_is_read_even_behind_an_http_error(self) -> None:
        cases = {
            "not found behind 404": (404, {"responseCode": 100}, ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE),
            "resolved behind 404": (404, {"responseCode": 1}, ResolverState.DOI_RESOLVED),
            "error code behind 500": (500, {"responseCode": 2}, ResolverState.SOURCE_UNAVAILABLE),
        }
        for label, (status, body, state) in cases.items():
            with self.subTest(case=label):
                answer = self.lookup(raises_handle_error(status, body))
                self.assertEqual((answer.state, answer.http_status, answer.handle_response_code),
                                 (state, status, body["responseCode"]))
                self.assertIsNotNone(answer.provenance["response_sha256"])

    def test_resolved_needs_body_code_one_whatever_the_status(self) -> None:
        answer = self.lookup(FakeResponse(json.dumps({"responseCode": 1}).encode(), 200))
        self.assertIs(answer.state, ResolverState.DOI_RESOLVED)
        self.assertIn("HTTP status 200 not used", answer.diagnostics[0])

    def test_answers_without_a_body_code_are_source_unavailable(self) -> None:
        bodies = {
            "html": b"<html>synthetic error page</html>",
            "no code": json.dumps({"handle": self.DOI}).encode(),
            "boolean code": json.dumps({"responseCode": True}).encode(),
            "string code": json.dumps({"responseCode": "1"}).encode(),
            "array": b"[1]",
            "empty": b"",
        }
        for label, body in bodies.items():
            with self.subTest(body=label):
                answer = self.lookup(FakeResponse(body, 200))
                self.assertIs(answer.state, ResolverState.SOURCE_UNAVAILABLE)
                self.assertIsNone(answer.handle_response_code)
                self.assertTrue(answer.diagnostics[0].startswith("RESPONSE_UNUSABLE"), answer.diagnostics)

    def test_network_failures_and_oversized_bodies_are_source_unavailable(self) -> None:
        for failure in (OSError("synthetic"), urllib.error.URLError("synthetic"), TimeoutError("synthetic")):
            with self.subTest(failure=type(failure).__name__):
                answer = self.lookup(failure)
                self.assertIs(answer.state, ResolverState.SOURCE_UNAVAILABLE)
                self.assertTrue(answer.diagnostics[0].startswith("NETWORK_ERROR"))
        answer = self.lookup(FakeResponse(b" " * (handle_adapter.MAX_RESPONSE_BYTES + 1)))
        self.assertTrue(answer.diagnostics[0].startswith("RESPONSE_TOO_LARGE"))

    def test_it_asks_the_handle_api_through_the_opener_only_and_only_when_live(self) -> None:
        opener = ScriptedOpener(FakeResponse(json.dumps({"responseCode": 100}).encode()))
        with self.assertRaises(live_adapter.LiveAccessRefused):
            handle_adapter.lookup(self.DOI, NetworkPolicy(opener=opener))
        self.assertEqual(opener.calls, [])
        policy = NetworkPolicy(live=True, opener=opener, timeout_seconds=7, user_agent="synthetic-agent/2")
        answer = handle_adapter.lookup(self.DOI, policy)
        (request, timeout), = opener.calls
        self.assertEqual(request.full_url, "https://doi.org/api/handles/10.5555/science-gate-canary-0123456789ab")
        self.assertEqual((timeout, request.get_header("User-agent")), (7, "synthetic-agent/2"))
        self.assertEqual(answer.provenance["resolver_identity"], handle_adapter.RESOLVER_IDENTITY)
        self.assertIs(answer.provenance["live_refresh_performed"], True)


def handle_then(resolver: Any) -> Any:
    """Body code 100 from the Handle API, then ``resolver`` for content negotiation."""

    def answer(request: Any) -> Any:
        if request.full_url.startswith(handle_adapter.HANDLE_API_URL):
            raise handle_error(request, 404, {"responseCode": 100})
        return resolver(request)

    return answer


def unreachable(request: Any) -> Any:
    raise OSError("synthetic: the resolver is unreachable")


class LiveCanaryTests(TempDirTestCase):
    """``live.canary_check``: the Handle API must say 100, then the same resolver must say "not found"."""

    CANARY = canary_doi(PREFIX, canary_nonce(RUN_ID))

    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()

    def check(self, answer: Any) -> tuple[Any, list[str]]:
        opener = ScriptedOpener(answer)
        check = live_adapter.canary_check(PREFIX, RUN_ID, live_policy(opener))
        self.assertEqual((check.doi, check.source), (self.CANARY, "live"))
        return check, [request.full_url for request, _ in opener.calls]

    def test_it_holds_only_when_both_halves_say_the_doi_does_not_exist(self) -> None:
        for status in live_adapter.NOT_FOUND_STATUSES:
            with self.subTest(status=status):
                check, urls = self.check(handle_then(raises_handle_error(status, {})))
                self.assertEqual((check.holds, check.resolved, check.handle_response_code), (True, False, 100))
                self.assertEqual(urls, [handle_adapter.request_url(self.CANARY), live_adapter.request_url(self.CANARY)])
                self.assertEqual(check.detail, f"CANARY_HOLDS: body responseCode 100, and the resolver answered HTTP {status}")

    def test_body_code_one_is_a_proven_miss_and_ends_the_check(self) -> None:
        check, urls = self.check(yes_to_everything)
        self.assertEqual((check.holds, check.resolved, check.state), (False, True, ResolverState.DOI_RESOLVED))
        self.assertEqual(urls, [handle_adapter.request_url(self.CANARY)], "a proven miss needs no second call")

    def test_a_resolver_that_invents_a_record_is_a_proven_miss_even_behind_an_honest_handle(self) -> None:
        check, urls = self.check(handle_then(invented_metadata))
        self.assertEqual((check.holds, check.resolved, check.handle_response_code), (False, True, 100))
        self.assertTrue(check.detail.startswith("CANARY_RESOLVED: the resolver returned the work"), check.detail)
        self.assertEqual(len(urls), 2)

    def test_anything_short_of_two_definite_noes_leaves_the_canary_unconfirmed(self) -> None:
        cases = {
            "values not found": metadata_then({"responseCode": 200}),
            "handle error code": metadata_then({"responseCode": 2}, 500),
            "handle unreachable": unreachable,
            "resolver unreachable": handle_then(unreachable),
            "resolver error status": handle_then(raises_handle_error(503, {})),
        }
        for label, answer in cases.items():
            with self.subTest(case=label):
                check, _ = self.check(answer)
                self.assertEqual((check.holds, check.resolved), (False, False))
                self.assertTrue(check.detail.startswith("CANARY_NOT_CONFIRMED"), check.detail)

    def test_without_a_run_id_no_canary_is_asked(self) -> None:
        opener = failing_opener()
        check = live_adapter.canary_check(PREFIX, None, live_policy(opener))
        self.assertEqual((check.holds, check.resolved, check.source, check.doi), (False, False, "none", None))
        self.assertTrue(check.detail.startswith("NO_RUN_ID"))
        self.assertEqual(opener.calls, [])



# ---------------------------------------------------------------------------
# Frozen canaries, body codes and registration in the capture
# ---------------------------------------------------------------------------


class FrozenControlTests(unittest.TestCase):
    def test_a_captured_canary_holds_only_as_not_found_with_body_code_100(self) -> None:
        check = canary_check(PREFIX, parse_frozen(frozen_document()))
        self.assertEqual((check.holds, check.resolved, check.source), (True, False, "frozen"))
        self.assertEqual(check.to_dict()["handle_response_code"], 100)
        self.assertTrue(check.detail.startswith("CANARY_HOLDS"))

    def test_a_canary_that_reaches_anything_is_a_proven_miss(self) -> None:
        cases = {
            "body code 1": canary_record(outcome="FOUND", http_status=200, handle_response_code=1),
            "found with a work, no code": {
                **canary_record(outcome="FOUND", http_status=200, work=dict(WORK_A, doi=canary_doi(PREFIX, "0" * 12))),
                "doi": canary_doi(PREFIX, "0" * 12),
                "handle_response_code": None,
            },
        }
        for label, record in cases.items():
            with self.subTest(case=label):
                check = canary_check(PREFIX, parse_frozen(frozen_document(record, canary=False)))
                self.assertEqual((check.holds, check.resolved), (False, True))
                self.assertTrue(check.detail.startswith("CANARY_RESOLVED"), check.detail)

    def test_a_canary_that_neither_holds_nor_resolves_leaves_coverage_unknown(self) -> None:
        incomplete = {key: value for key, value in canary_record().items() if key != "response_sha256"}
        cases = {
            "values not found": (canary_record(handle_response_code=200), "CANARY_NOT_CONFIRMED"),
            "no body code": (canary_record(handle_response_code=None), "CANARY_NOT_CONFIRMED"),
            "missing provenance": (incomplete, "CANARY_UNUSABLE"),
            "absent": (None, "NO_CANARY"),
        }
        for label, (record, code) in cases.items():
            with self.subTest(case=label):
                records = () if record is None else (record,)
                check = canary_check(PREFIX, parse_frozen(frozen_document(*records, canary=False)))
                self.assertEqual((check.holds, check.resolved), (False, False))
                self.assertTrue(check.detail.startswith(code), check.detail)
        self.assertTrue(canary_check(PREFIX, None).detail.startswith("NO_CANARY"))

    def test_canary_records_are_structural(self) -> None:
        documents = {
            "two canaries for one prefix": frozen_document(canary_record(nonce="a" * 12)),
            "canary flag on an ordinary DOI": frozen_document(found(WORK_A["doi"], canary=True), canary=False),
            "canary flag that is not a boolean": frozen_document(canary_record(canary="yes"), canary=False),
            "negative body code": frozen_document(canary_record(handle_response_code=-1), canary=False),
            "boolean body code": frozen_document(canary_record(handle_response_code=True), canary=False),
        }
        for label, document in documents.items():
            with self.subTest(case=label), self.assertRaises(RecordFormatError):
                parse_frozen(document)

    def test_a_canary_is_never_a_reference_work(self) -> None:
        resolving = {
            **canary_record(outcome="FOUND", http_status=200, handle_response_code=1),
            "work": dict(WORK_A, doi=canary_doi(PREFIX, "0123456789ab")),
        }
        works = parse_frozen(frozen_document(found(WORK_B["doi"]), resolving, canary=False)).resolved_works()
        self.assertEqual([work.doi for work in works], [WORK_B["doi"]])

    def test_c_a_body_code_overrides_the_outcome_and_the_http_status(self) -> None:
        frozen = parse_frozen(frozen_document(found(WORK_A["doi"], http_status=200, handle_response_code=200)))
        answer = resolve(WORK_A["doi"], frozen)
        self.assertIs(answer.state, ResolverState.DOI_NOT_RESOLVED_AT_CAPTURE)
        self.assertIsNone(answer.work, "a DOI that did not resolve never supplies a reference work")
        self.assertEqual((answer.http_status, answer.handle_response_code), (200, 200))
        self.assertTrue(any(item.startswith("HANDLE_CODE_DECIDES") for item in answer.diagnostics))
        self.assertEqual(frozen.resolved_works(), ())

        behind_404 = parse_frozen(frozen_document(found(WORK_A["doi"], http_status=404, handle_response_code=1)))
        self.assertIs(resolve(WORK_A["doi"], behind_404).state, ResolverState.DOI_RESOLVED)
        error = parse_frozen(frozen_document(found(WORK_A["doi"], handle_response_code=2)))
        self.assertIs(resolve(WORK_A["doi"], error).state, ResolverState.SOURCE_UNAVAILABLE)

    def test_body_code_one_without_a_captured_work_vouches_for_nothing(self) -> None:
        record = {**not_found(WORK_A["doi"]), "handle_response_code": 1}
        answer = resolve(WORK_A["doi"], parse_frozen(frozen_document(record)))
        self.assertIs(answer.state, ResolverState.SOURCE_UNAVAILABLE)
        self.assertTrue(answer.diagnostics[0].startswith("NO_REFERENCE_WORK"))

    def test_a_capture_older_than_the_registration_is_source_unavailable_never_not_found(self) -> None:
        for record in (not_found(WORK_A["doi"]), found(WORK_A["doi"])):
            with self.subTest(outcome=record["outcome"]):
                stale = {**record, "registered_at": "2026-03-01T00:00:00Z"}  # captured 2026-02-14
                answer = resolve(WORK_A["doi"], parse_frozen(frozen_document(stale)))
                self.assertIs(answer.state, ResolverState.SOURCE_UNAVAILABLE)
                self.assertIn("SNAPSHOT_PREDATES_REGISTRATION: captured at 2026-02-14T09:00:00Z, but the DOI was "
                              "registered at 2026-03-01T00:00:00Z", answer.diagnostics[0])
        current = {**found(WORK_A["doi"]), "registered_at": "2026-02-14T09:00:00Z"}
        self.assertIs(resolve(WORK_A["doi"], parse_frozen(frozen_document(current))).state, ResolverState.DOI_RESOLVED)
        invalid = {**found(WORK_A["doi"]), "registered_at": "2026-02-30"}
        answer = resolve(WORK_A["doi"], parse_frozen(frozen_document(invalid)))
        self.assertEqual(answer.diagnostics, ("INVALID_FIELD: registered_at",))


# ---------------------------------------------------------------------------
# Through the engine
# ---------------------------------------------------------------------------


class ResolverControlTests(CitationProjectCase):
    def resolver(self, run: Any) -> Any:
        return self.check(run, "citation_resolver")

    def assert_no_doi_resolved(self, run: Any) -> None:
        resolutions = self.resolver(run).evidence["resolutions"]
        self.assertTrue(resolutions)
        self.assertEqual({item["state"] for item in resolutions}, {"SOURCE_UNAVAILABLE"})
        self.assertEqual(self.resolver(run).evidence["state_totals"]["DOI_RESOLVED"], 0)
        for item in self.check(run, "citation_metadata").evidence["citations"]:
            self.assertEqual((item["resolver_state"], item["reference"]), ("SOURCE_UNAVAILABLE", None))

    def test_a_an_opener_that_says_yes_to_everything_makes_the_canary_resolve(self) -> None:
        opener = ScriptedOpener(yes_to_everything)
        run = self.run_project(frozen=None, live=True, opener=opener)
        resolver = self.resolver(run)
        self.assertOutcome(resolver, Status.FAIL, Reason.BLIND_SPOT, FailureMode.VACUOUS_PASS)
        self.assert_no_doi_resolved(run)
        canary = canary_doi(PREFIX, canary_nonce(run.result.run_id))
        live = resolver.evidence["live_canaries"][PREFIX]
        self.assertEqual((live["doi"], live["state"], live["handle_response_code"], live["holds"]),
                         (canary, "DOI_RESOLVED", 1, False))
        self.assertEqual(resolver.evidence["distrusted_prefixes"], [PREFIX])
        self.assertEqual(handle_urls(opener), [handle_adapter.request_url(canary)], "one canary per prefix per run")
        self.assertEqual(len(opener.calls), 4, "three cited DOIs and one canary")
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.FAIL, Reason.BLIND_SPOT, 1))

    def test_a_frozen_canary_that_resolved_distrusts_the_whole_prefix(self) -> None:
        resolving = canary_record(outcome="FOUND", http_status=200, handle_response_code=1)
        frozen = frozen_document(found(WORK_A["doi"]), found(WORK_B["doi"]), found(WORK_C["doi"]), resolving,
                                 canary=False)
        run = self.run_project(frozen=frozen)
        self.assertOutcome(self.resolver(run), Status.FAIL, Reason.BLIND_SPOT, FailureMode.VACUOUS_PASS)
        self.assert_no_doi_resolved(run)
        self.assertEqual(self.check(run, "citation_metadata").evidence["reference_pool"], [],
                         "works the distrusted capture returned are never references")
        self.assertIn("CANARY_RESOLVED", self.resolver(run).evidence["resolutions"][0]["diagnostics"][-1])
        self.assertEqual(self.opener.calls, [])

    def test_b_a_frozen_set_without_a_canary_cannot_pass(self) -> None:
        frozen = frozen_document(found(WORK_A["doi"]), found(WORK_B["doi"]), found(WORK_C["doi"]), canary=False)
        run = self.run_project(frozen=frozen)
        resolver = self.resolver(run)
        self.assertOutcome(resolver, Status.ABSTAIN, Reason.BLIND_SPOT, FailureMode.VACUOUS_PASS)
        self.assertEqual(resolver.evidence["state_totals"]["DOI_RESOLVED"], 3, "the answers stand; they are unvouched")
        canary = resolver.evidence["canaries"][PREFIX]
        self.assertEqual((canary["holds"], canary["source"], canary["doi"]), (False, "none", None))
        self.assertIn("NO_CANARY", resolver.diagnostics[0])
        self.assertNotEqual(run.status, Status.PASS)
        self.assertEqual((run.result.reason, run.exit_code), (Reason.BLIND_SPOT, 2))

    def test_b_an_unconfirmed_canary_cannot_vouch_either(self) -> None:
        cases = {
            "values not found": canary_record(handle_response_code=200),
            "missing provenance": {key: value for key, value in canary_record().items() if key != "retrieved_at"},
        }
        for label, record in cases.items():
            with self.subTest(case=label):
                frozen = frozen_document(found(WORK_A["doi"]), found(WORK_B["doi"]), found(WORK_C["doi"]), record,
                                         canary=False)
                self.assertOutcome(self.resolver(self.run_project(frozen=frozen)), Status.ABSTAIN, Reason.BLIND_SPOT)

    def test_a_resolver_that_invents_the_canary_distrusts_its_live_answers(self) -> None:
        opener = ScriptedOpener(handle_then(invented_metadata))
        run = self.run_project(frozen=None, live=True, opener=opener)
        self.assertOutcome(self.resolver(run), Status.FAIL, Reason.BLIND_SPOT, FailureMode.VACUOUS_PASS)
        self.assert_no_doi_resolved(run)

    def test_an_unconfirmed_live_canary_cannot_vouch_for_live_answers(self) -> None:
        opener = ScriptedOpener(metadata_then({"responseCode": 200}))
        run = self.run_project(frozen=None, live=True, opener=opener)
        resolver = self.resolver(run)
        self.assertOutcome(resolver, Status.ABSTAIN, Reason.BLIND_SPOT, FailureMode.VACUOUS_PASS)
        self.assertEqual(resolver.evidence["state_totals"]["DOI_RESOLVED"], 3)
        self.assertFalse(resolver.evidence["live_canaries"][PREFIX]["holds"])

    def test_an_honest_live_canary_lets_live_answers_pass(self) -> None:
        """With a frozen set declared (here absent on disk), the falsifier can stage its NOT_FOUND in memory."""
        path = self.build(frozen=None, live=True)
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["citations"]["frozen"] = "citations/frozen.json"
        self.write_manifest(manifest, "project/manifest.json")
        opener = ScriptedOpener(metadata_then({"responseCode": 100}, 404))
        run = verify(path, network=NetworkPolicy(opener=opener))
        resolver = self.resolver(run)
        self.assertEqual(resolver.verdict, Status.PASS, resolver.diagnostics)
        self.assertTrue(resolver.evidence["live_canaries"][PREFIX]["holds"])
        self.assertEqual(resolver.evidence["canaries"], {}, "the capture answered nothing, so needs none")
        self.assertEqual(resolver.evidence["falsification"], "WITNESSED")
        self.assertEqual(len(handle_urls(opener)), 1, "the overlay reuses the run's live answers and canary")
        self.assertEqual(len(opener.calls), 5, "three cited DOIs, then the canary's Handle and resolver halves")

    def test_a_live_only_resolver_without_a_declared_capture_cannot_be_witnessed(self) -> None:
        """No frozen set is declared, so no known-bad answer can be staged offline: the PASS stays unwitnessed."""
        opener = ScriptedOpener(metadata_then({"responseCode": 100}, 404))
        resolver = self.resolver(self.run_project(frozen=None, live=True, opener=opener))
        self.assertOutcome(resolver, Status.ABSTAIN, Reason.BLIND_SPOT, FailureMode.VACUOUS_PASS)
        self.assertEqual(resolver.evidence["falsification"], "NO_CASE")
        self.assertTrue(resolver.evidence["live_canaries"][PREFIX]["holds"], "the canary itself held")

    def test_a_live_canary_is_asked_only_after_a_live_positive(self) -> None:
        failing = failing_opener()
        self.run_project(frozen=frozen_document(found(WORK_A["doi"]), found(WORK_B["doi"])), live=True, opener=failing)
        self.assertEqual(len(failing.calls), 1, "requirement 17: exactly the one missing DOI, and no canary")

        covered = failing_opener()
        self.run_project(live=True, opener=covered)
        self.assertEqual(covered.calls, [], "a capture that answers everything needs no live call at all")

        mismatch = ScriptedOpener(FakeResponse(json.dumps(csl_for(WORK_A)).encode()))
        run = self.run_project(frozen=frozen_document(found(WORK_A["doi"]), found(WORK_B["doi"])), live=True,
                               opener=mismatch)
        self.assertEqual(handle_urls(mismatch), [], "a target mismatch is not a positive to vouch for")
        self.assertEqual(self.resolver(run).verdict, Status.FAIL)

    def test_c_values_not_found_in_the_capture_is_not_resolved(self) -> None:
        record = found(WORK_B["doi"], http_status=200, handle_response_code=200)
        run = self.run_project(frozen=frozen_document(found(WORK_A["doi"]), record, found(WORK_C["doi"])))
        resolver = self.resolver(run)
        self.assertOutcome(resolver, Status.FAIL, Reason.SOURCE_MISMATCH, FailureMode.SOURCE_MISMATCH)
        states = {item["doi"]: (item["state"], item["handle_response_code"], item["http_status"])
                  for item in resolver.evidence["resolutions"]}
        self.assertEqual(states[WORK_B["doi"]], ("DOI_NOT_RESOLVED_AT_CAPTURE", 200, 200))

    def test_a_stale_capture_is_source_unavailable_through_the_engine(self) -> None:
        stale = {**not_found(WORK_C["doi"]), "registered_at": "2026-03-01T00:00:00Z"}
        run = self.run_project(frozen=frozen_document(found(WORK_A["doi"]), found(WORK_B["doi"]), stale))
        resolver = self.resolver(run)
        self.assertOutcome(resolver, Status.ABSTAIN, Reason.SOURCE_UNAVAILABLE)
        self.assertEqual(resolver.evidence["state_totals"]["DOI_NOT_RESOLVED_AT_CAPTURE"], 0, "never 'not found'")
        self.assertIn("SNAPSHOT_PREDATES_REGISTRATION", resolver.diagnostics[0])

    def test_committed_fixtures_for_the_controls_work_offline(self) -> None:
        block_sockets(self)
        expectations = {
            "canary-missing": (Status.ABSTAIN, Reason.BLIND_SPOT),
            "canary-resolved": (Status.FAIL, Reason.BLIND_SPOT),
            "handle-values-not-found": (Status.FAIL, Reason.SOURCE_MISMATCH),
            "impossible-timeline": (Status.ABSTAIN, Reason.UNVERIFIED),
        }
        for name, outcome in expectations.items():
            with self.subTest(fixture=name):
                opener = failing_opener()
                run = verify(FIXTURES / name / "manifest.json", network=NetworkPolicy(opener=opener))
                self.assertEqual((run.status, run.result.reason), outcome)
                self.assertEqual(opener.calls, [])


class ImpossibleTimelineTests(CitationProjectCase):
    """(d): nothing can be verified before it exists."""

    def project(self, log_retrieved_at: str, *, registered_at: str | None = REGISTERED_AT, **build: Any) -> Any:
        first = found(WORK_A["doi"], retrieved_at=LATER_CAPTURE)
        if registered_at is not None:
            first["registered_at"] = registered_at
        log = log_document(
            [("C1", "VERIFIED"), ("C2", "VERIFIED"), ("C3", "VERIFIED")],
            [invocation("inv-1", "C1", retrieved_at=log_retrieved_at), invocation("inv-2", "C2"),
             invocation("inv-3", "C3")],
        )
        build.setdefault("frozen", frozen_document(first, found(WORK_B["doi"]), found(WORK_C["doi"])))
        return self.run_project(log=log, **build)

    def test_d_the_worked_example_is_narrated_with_both_timestamps(self) -> None:
        run = self.project(LOG_RETRIEVED_AT)
        result = self.check(run, "verification_log")
        self.assertOutcome(result, Status.ABSTAIN, Reason.UNVERIFIED, FailureMode.NARRATED_VERIFICATION)
        timeline = result.evidence["timeline"]
        self.assertEqual(
            timeline["impossible"],
            [
                {
                    "invocation_id": "inv-1",
                    "citation_id": "C1",
                    "doi": WORK_A["doi"],
                    "retrieved_at": "2026-04-01T00:00:00Z",
                    "registered_at": "2026-05-01T00:00:00Z",
                }
            ],
        )
        self.assertEqual((timeline["state"], timeline["invocations_judged"], timeline["registration_unknown"],
                          timeline["impossible_count"]), ("ASSESSED", 1, 2, 1))
        self.assertEqual(result.evidence["narrated"], ["C1"])
        detail = next(item for item in result.diagnostics if item.startswith("IMPOSSIBLE_TIMELINE"))
        self.assertIn("retrieved at 2026-04-01T00:00:00Z", detail)
        self.assertIn("registered at 2026-05-01T00:00:00Z", detail)
        self.assertEqual(result.evidence["invocation_records"]["impossible_timeline_count"], 1)
        self.assertTrue(self.invariant(run, "checked_claims_le_invocations").violated, "3 claimed, 2 possible")
        self.assertEqual((run.status, run.result.reason, run.exit_code), (Status.ABSTAIN, Reason.UNVERIFIED, 2))

    def test_a_retrieval_at_or_after_registration_backs_the_claim(self) -> None:
        for retrieved_at in (REGISTERED_AT, "2026-05-01T00:00:01Z"):
            with self.subTest(retrieved_at=retrieved_at):
                result = self.check(self.project(retrieved_at), "verification_log")
                self.assertEqual(result.verdict, Status.PASS, result.diagnostics)
                self.assertEqual(result.evidence["timeline"]["impossible"], [])

    def test_an_unknown_registration_is_not_judged_and_not_assumed(self) -> None:
        result = self.check(self.project(LOG_RETRIEVED_AT, registered_at=None), "verification_log")
        self.assertEqual(result.verdict, Status.PASS)
        timeline = result.evidence["timeline"]
        self.assertEqual((timeline["invocations_judged"], timeline["registration_unknown"]), (0, 3))

    def test_without_a_capture_the_timeline_is_not_assessed(self) -> None:
        result = self.check(self.project(LOG_RETRIEVED_AT, frozen=None), "verification_log")
        timeline = result.evidence["timeline"]
        self.assertEqual((timeline["state"], timeline["impossible_count"], timeline["invocations_judged"]),
                         ("NOT_ASSESSED", None, None))
        self.assertEqual(result.verdict, Status.PASS, "the structural claim is still backed")


# ---------------------------------------------------------------------------
# The resolver's falsifier (section 17.5)
# ---------------------------------------------------------------------------


class ResolverFalsifierTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fixed_clock()
        block_sockets(self)

    def subject(self, fixture: str) -> Any:
        """The resolver's recorded result in a real run of ``fixture``."""
        run = verify(FIXTURES / fixture / "manifest.json", network=NetworkPolicy(opener=failing_opener()))
        (resolver,) = [item for item in run.result.checks if item.check_id == "doi-resolution"]
        return resolver

    def test_the_case_replaces_the_first_resolved_doi_and_the_real_checker_rejects_it(self) -> None:
        ctx, specs = context_for(FIXTURES / "all-good" / "manifest.json")
        spec = specs["doi-resolution"]
        self.assertEqual(check_resolver(ctx, spec).verdict, Status.PASS)
        (case,) = falsify_resolver(ctx, spec, self.subject("all-good"))
        self.assertEqual((case.case_id, case.expected_verdict, case.expected_reason),
                         ("capture-not-found", Status.FAIL, Reason.SOURCE_MISMATCH))
        (path, data), = case.documents.items()
        self.assertEqual(path, "citations/frozen.json")
        records = {record["doi"]: record for record in strict_loads(data)["records"]}
        replaced = records["10.5555/sgate.fx.0001"]
        self.assertEqual((replaced["outcome"], replaced["handle_response_code"], replaced["work"]),
                         ("NOT_FOUND", 100, None))
        self.assertEqual(len(records), 4, "the other answers and the canary are kept")
        rejected = check_resolver(ctx.overlay(case), spec)
        self.assertEqual((rejected.verdict, rejected.reason), (Status.FAIL, Reason.SOURCE_MISMATCH))

    def test_the_engine_records_the_resolver_pass_as_witnessed(self) -> None:
        resolver = self.subject("all-good")
        self.assertEqual((resolver.verdict, resolver.evidence["falsification"]), (Status.PASS, "WITNESSED"))
        (record,) = resolver.evidence["falsifiers"]
        self.assertEqual((record["case_id"], record["outcome"]), ("capture-not-found", "REJECTED"))

    def test_no_case_without_a_resolved_doi(self) -> None:
        ctx, specs = context_for(FIXTURES / "canary-resolved" / "manifest.json")
        self.assertEqual(falsify_resolver(ctx, specs["doi-resolution"], self.subject("canary-resolved")), ())


if __name__ == "__main__":
    unittest.main()
