# scientific-evidence-gate — architecture and contracts

This file is the binding contract for every module. Where it says MUST, tests
enforce it. Governing rule:

> A passing check must emit enough evidence to prove that it had the
> opportunity to fail.

Evidence boundary, kept separate in every output:

1. **Integrity** — was this the exact artifact, input, execution and version claimed?
2. **Performance** — how did the fixed system behave on a declared evaluation?
3. **Scientific validity** — does the conclusion hold in the intended domain? *Never established by this tool.*

## 0. Ground rules

- Python ≥ 3.11, standard library only at runtime. No runtime dependencies.
- The package is `science_gate` under `src/`. The distribution is
  `scientific-evidence-gate` and the console script is `science-gate`.
- License field: `NOASSERTION`. No LICENSE file. No `authors` field (it will not
  be invented).
- There is no `shell=True`, and no process is ever built from manifest or
  input text. The package never starts a subprocess at all, except the test
  suite running the CLI.
- Every write goes through `science_gate._safeio.safe_write(root, relpath, data)`.
  That function refuses any path that resolves outside `root`, including via
  `..`, absolute paths, drive letters, or symlinks.
- Determinism: sort every mapping and set before output; use no `hash()`-order
  iteration. Time comes only from `_clock.now()`, which honors the
  `SCIENCE_GATE_FIXED_TIME` environment variable (ISO-8601 UTC, `Z`
  suffix). Identifiers derive from content hashes plus a sequence, never from
  random numbers. `uuid4` is forbidden.
- Numbers in canonical JSON are integers only. Any non-integer quantity is
  serialized as a decimal string, e.g. `"0.125"`. Floats never enter hashed
  content.
- Missing evidence is never converted into zero, false, PASS, or "no defects".
  An absent count is JSON `null` together with an explicit state.

## 1. Vocabulary (`models.py`)

```python
class Status(str, Enum):  PASS="PASS"; FAIL="FAIL"; ABSTAIN="ABSTAIN"; ERROR="ERROR"
EXIT_CODE = {PASS: 0, FAIL: 1, ABSTAIN: 2, ERROR: 3}
class Reason(str, Enum):  VERIFIED, UNVERIFIED, INVALID_BASELINE, BLIND_SPOT, INSUFFICIENT_EVIDENCE,
                          SOURCE_UNAVAILABLE, SOURCE_MISMATCH, PROTOCOL_BROKEN, PARTIAL_EXECUTION,
                          OUT_OF_SCOPE, REQUIRES_HUMAN_REVIEW
class FailureMode(str, Enum): VACUOUS_PASS, NARRATED_VERIFICATION, PARTIAL_EXECUTION, DEFECTIVE_VERIFICATION,
                          OMITTED_POPULATION, SOURCE_MISMATCH, PROTOCOL_DRIFT, EPHEMERAL_CLAIM, STALE_DEPENDENCY
class ExecutionState(str, Enum): CHECKED, SKIPPED, NOT_APPLICABLE
class InvocationResult(str, Enum): STARTED (non-terminal), COMPLETED, ERRORED, ABSTAINED
class DenominatorSource(str, Enum): INDEPENDENT, OBSERVED, ESTIMATED, UNAVAILABLE
class Validity(str, Enum): CURRENT, STALE_PENDING_REVALIDATION, REVALIDATED_UNCHANGED, REVALIDATED_CHANGED,
                          SUPERSEDED, INVALIDATED, UNRESOLVED
class ResolverState(str, Enum): DOI_RESOLVED, DOI_NOT_RESOLVED_AT_CAPTURE, DOI_TARGET_MISMATCH, SOURCE_UNAVAILABLE
class MetadataState(str, Enum): VERIFIED_WITHIN_DECLARED_SCOPE, FIELD_MISMATCH, CONFLATED_ENTRY,
                          RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES
class AccessClass(str, Enum): PUBLIC, REFERENCE_ONLY, SYNTHETIC, CONTROLLED_LOCAL
class SignatureState(str, Enum): UNSIGNED, SIGNED_HMAC_SHA256
@dataclass(frozen=True) class Permissions: evaluation_allowed=True, training_allowed=False,
                          redistribution_allowed=False, derivatives_allowed=False,
                          public_display_allowed=False, commercial_use_allowed=False
```

Result types (frozen dataclasses with `to_dict()`, sorted, JSON-safe):

- `CheckResult(check_id, kind, version, required, execution_state, verdict: Status, reason: Reason,
  failure_modes: tuple, rows_examined: int|None, inputs: tuple[input_id], evidence: dict, diagnostics: tuple[str],
  invocation_id: str|None)`
- `InvariantResult(name, applicable: bool, holds: bool|None, detail: str)`. `holds` is None when not applicable.
- `RunResult(status, reason, reasons: tuple, failure_modes: tuple, run_id, accounting: InputAccounting,
  checks: tuple[CheckResult], invariants: tuple[InvariantResult], evidence_manifest_sha256, started_at, completed_at,
  counters: dict)`

SARIF alignment (reports only): a `CheckResult` maps to SARIF `result.kind` as
follows. `pass` = CHECKED+PASS. `fail` = CHECKED+FAIL. `notApplicable` =
NOT_APPLICABLE. `review` = ABSTAIN with REQUIRES_HUMAN_REVIEW. `open` = SKIPPED
or any other ABSTAIN. `ERROR` becomes `fail` with level `error`, plus a
`toolExecutionNotification`.

## 2. Manifest (`manifests.py`, schema `schemas/manifest.schema.json`)

JSON only. `schema` must equal `"science-gate-manifest/v1"`; anything else is
an ERROR with PROTOCOL_BROKEN. Paths are relative to the manifest's directory.

```json
{
  "schema": "science-gate-manifest/v1",
  "run_label": "demo-valid",
  "inputs": [
    {"id": "measurements", "path": "data/measurements.csv", "required": true, "format": "csv",
     "sha256": "<optional expected digest>", "row_key": ["sample_id"],
     "expected_rows": 12, "denominator_source": "INDEPENDENT"}
  ],
  "accepted_snapshot": "snapshots/accepted.json",
  "checks": [
    {"id": "rows", "kind": "row_count", "version": "1", "required": true, "inputs": ["measurements"], "params": {}}
  ],
  "claims": "claims/registry.json",
  "manuscript": "claims/manuscript.md",
  "dependencies": "graph/graph.json",
  "citations": {"entries": "citations/entries.json", "log": "citations/verification-log.json",
                "frozen": "citations/frozen.json", "live": false},
  "reviews": {"required_reviewers": ["reviewer-a", "reviewer-b"], "verdicts": "reviews/verdicts.json"},
  "time_sources": "time/events.json",
  "limits": {"max_file_bytes": 52428800, "max_files": 10000, "max_rows": 1000000},
  "corpus": {"access_class": "SYNTHETIC", "permissions": {}},
  "summary_claim": "claims/summary.json"
}
```

Validation rules (each violation yields an ERROR with a named diagnostic):

- Unknown top-level keys are refused.
- Any key named `command`, `cmd`, `shell`, `exec`, `script`, `run`, `subprocess`
  or `entrypoint`, at any depth, is refused (UNSAFE_SUBPROCESS_REQUEST).
- Two entries resolving to the same normalized path are refused (DUPLICATE_PATH).
  Paths are compared case-insensitively on Windows.
- Manifest JSON that cannot be parsed produces MALFORMED_JSON, never a traceback.
- `required` defaults to true. A check `kind` must be registered (see §5).

## 3. Discovery and input accounting (`discovery.py`)

`discover(manifest) -> (InputAccounting, dict[input_id, OpenedInput])`

`InputAccounting` carries these counters, each an int or None, and each with a
`denominator_source`: `expected, discovered, opened, parsed, examined, admitted,
excluded, deferred, unresolved, failed`. It also carries per-input records with
`path`, `sha256`, `bytes`, `rows`, `state`, and a `closure` block:

`{"source": "INDEPENDENT|OBSERVED|ESTIMATED|UNAVAILABLE", "holds": true|false|null, "expected": n|null, "accounted": n|null}`

- **Closure** holds when `admitted + excluded + deferred + unresolved + failed == expected`.
  It is enforced **only** when the source is INDEPENDENT.
- **Without an INDEPENDENT source**, `holds` is null. This is never shown as true.
- **Before a file is opened**, safety applies: symlinks and `..` must resolve
  under the root, the size must be at most `max_file_bytes`, and the number of
  files must be at most `max_files`. On failure the input's state is `REFUSED`
  with a diagnostic.
- **Declared digests** are compared against the SHA-256, which is computed by
  streaming. A mismatch sets state `HASH_MISMATCH`, which makes the run FAIL
  with SOURCE_MISMATCH.
- **CSV** is parsed with the stdlib `csv` module. Values stay as strings, and
  numbers are parsed only through `invariants.parse_decimal`.
- **JSON** inputs are parsed strictly: duplicate keys are an error, and so are
  NaN and Infinity.
- **Empty or missing inputs** are counted as such, never as zero rows passed. A
  missing required input stays visible in the report as MISSING.

## 4. Execution ledger (`ledger.py`)

Every check execution is an **invocation**, recorded before it runs and closed
after. Ledger entries are JSON Lines, and each entry carries these fields:

`{seq, invocation_id, check_id, check_kind, check_version, input_ids, input_sha256s, started_at,
  completed_at|null, result: InvocationResult, evidence: {...}, verdict|null, reason|null,
  prev_entry_sha256, entry_sha256}`

- `invocation_id` = `inv-<first 12 hex of sha256(run_id + ":" + seq)>`.
- `entry_sha256` = sha256 of the canonical entry with `entry_sha256` omitted,
  so the entries form a hash chain. The run seals it with `ledger_head_sha256`
  and `ledger_length`.
- `Ledger.verify_chain(entries, head, length)` detects reordering, truncation,
  insertion, and edited entries.
- **Enforced invariants** (`invariants.py` runs these over the ledger and the
  results; each is named exactly as below):
  - `checked_claims_le_invocations`
  - `every_verdict_has_invocation`
  - `every_invocation_has_terminal_result`
  - `every_required_check_has_terminal_state`
  - `pass_requires_nonempty_evidence`
  - `pass_requires_complete_required_inputs`
  - `pass_requires_complete_required_checks`
  - `pass_requires_examined_rows`
  - `input_accounting_closure`
  - `ledger_chain_intact`

## 5. Checks (`verifier.py` registry)

A registry maps `kind` to the dotted path of a function, a `"module:function"`
string that is imported lazily. Manifests can only name registered kinds. Every
check function has this signature:

```python
def check(ctx: CheckContext, spec: CheckSpec) -> CheckOutcome
```

- `CheckContext` exposes the manifest, the opened inputs, the accepted
  snapshot, the manifest directory, the limits, and the injected
  `network: NetworkPolicy` (live off by default).
- `CheckOutcome(execution_state, verdict, reason, failure_modes, rows_examined, evidence, diagnostics)`.

Built-in kinds and their owners:

| kind | owner | purpose |
|---|---|---|
| `row_count` | verifier | rows examined > 0; closure against `expected_rows` when INDEPENDENT |
| `required_columns` | verifier | declared columns present |
| `duplicate_rows` | verifier | exact duplicates and duplicate `row_key` |
| `snapshot_completeness` | verifier | rows accepted in the snapshot are still present and unchanged (deleted rows → FAIL OMITTED_POPULATION) |
| `numeric_agreement` | invariants | compare declared values with stored values, rounding-aware and separator-aware |
| `reviewer_protocol` | verifier | all required reviewers present, no duplicate verdicts (→ ABSTAIN PROTOCOL_BROKEN, PROTOCOL_DRIFT) |
| `time_source` | verifier | declared timezone exists, normalized UTC exists, observation inside the requested window (mismatch → FAIL SOURCE_MISMATCH) |
| `verification_log` | citations | layer 1, structural: claimed verifications vs invocation records |
| `citation_resolver` | citations | layer 2, frozen by default |
| `citation_metadata` | citations | layer 3, metadata |
| `claim_registry` | claims | unregistered manuscript numbers; claims without a derivation |
| `dependency_currency` | dependencies | stale descendants block publication |
| `summary_consistency` | verifier | a stored PASS summary must match what was actually recomputed |

The engine runs every required check, even after a failure. A check that
raises is recorded as the invocation result ERRORED, with verdict ERROR and the
diagnostic text. A check with nothing to look at returns NOT_APPLICABLE. It
never returns PASS on an empty input.

## 6. Decision (`verifier.decide`) — the PASS contract

PASS is returned **only if all** of these hold:

- every required input exists, was opened and parsed, and has no hash mismatch
- `inputs_opened ≥ 1`
- `rows_examined ≥ 1` in scope
- `checks_executed == checks_expected` for the required checks
- every required check is terminal with verdict PASS
- no required check abstained or was skipped
- every applicable invariant holds
- the evidence manifest is non-empty

Otherwise the status is decided in this order:

1. **ERROR** — the manifest is invalid or unsafe, or an internal exception occurred.
2. **FAIL** — a required check reached FAIL, or an applicable invariant is
   definitively violated (hash mismatch, deleted row, time mismatch, closure
   broken).
3. **ABSTAIN** — anything missing, empty, skipped, unavailable, or unverified.
4. **PASS**.

The primary `reason` is taken from the highest-precedence finding. `reasons`
lists all of them, and `failure_modes` lists every taxonomy match.

The PASS report fields (all real values; `run.json` carries them at top
level):

- `status`, `run_id`
- `expected_inputs`, `inputs_discovered`, `inputs_opened`, `rows_examined`
- `checks_expected`, `checks_executed`, `checks_passed`, `checks_failed`, `checks_abstained`
- `evidence_manifest_sha256`
- `started_at`, `completed_at`

## 7. Claims (`claims.py`, `schemas/claims.schema.json`)

`registry.json` lists claims:

`{claim_id, statement, value: "12.4", unit, precision_decimals|null, derivation: {analysis_recipe, code_version,
environment, input_manifest_sha256}, stored_output: {path, sha256, selector}, review_state, publication_location}`

- Each claim resolves along the chain CLAIM → ANALYSIS RECIPE → CODE VERSION →
  ENVIRONMENT → INPUT MANIFEST → STORED OUTPUT → REVIEW STATE → PUBLICATION
  LOCATION. Every missing link is listed.
- A claim with no reproducible derivation is UNVERIFIED with the failure mode
  EPHEMERAL_CLAIM. It is never marked false.
- The manuscript scan finds numeric tokens in the manuscript; each is either
  matched to a registered claim value or listed as UNREGISTERED, with its line
  number. The run ABSTAINs with UNVERIFIED.
- A registered value is compared with its stored output through the numeric
  rules below.

**Numeric rules** (`invariants.parse_decimal` and `compare_decimal`), all using
`decimal.Decimal`:

- Thousands separators are accepted only when declared (`thousands=","`).
  They are removed before comparison, so "1,234" equals "1234" and can never
  evade it.
- An ambiguous string such as "1,234" with no declaration is
  REQUIRES_HUMAN_REVIEW.
- Agreement is **exact**, or **agreement at the stated precision**. The latter
  holds only when the stored value, rounded half-even to the number of decimals
  the claim prints, equals the claim. It is reported as
  `AGREES_AT_STATED_PRECISION`, with the precision.
- Two values that differ are never declared equal because both round to the
  same coarser value; the comparison is always stored value against claim
  string. So a claim of 0.1 against a stored 0.14 disagrees at precision 1
  unless the claim printed 0.1 and the stored value rounds to 0.1.

## 8. Dependencies (`dependencies.py`, `schemas/graph.schema.json`)

`graph.json` has `nodes` and `edges`:

- **nodes**: `{id, kind: SOURCE_SNAPSHOT|DESIGN|ADMITTED_EVIDENCE|ANALYSIS_RUN|RANKING_OR_MEASUREMENT|FIGURE_OR_TABLE|CONCLUSION, path|null, recorded_sha256, validity: Validity, history: []}`
- **edges**: `[[parent, child], …]`

Rules:

- A cycle is an ERROR.
- `impact(artifact_id)` walks descendants breadth-first in sorted order and
  marks them STALE_PENDING_REVALIDATION. It returns an impact report listing
  each descendant, its path from the changed node, its prior state, and a
  publication block. Nothing is called false or INVALIDATED.
- `detect_changes()` compares the current `sha256` of each node's file with
  `recorded_sha256`. A changed node starts an impact walk.
- `revalidate(artifact_id)` recomputes the node's hash. If it equals the
  recorded hash, the node becomes REVALIDATED_UNCHANGED, and descendants that
  are stale only because of this node may be cleared (early cutoff). If it
  differs, the node becomes REVALIDATED_CHANGED, the new hash is recorded, and
  its children stay stale.
- Every transition is appended to `history` as `{at, from, to, reason}`, so
  the original and corrected states are both preserved.
- State is persisted in `graph-state.json` next to the graph, using a safe
  write.
- The `dependency_currency` check fails publication (FAIL with
  STALE_DEPENDENCY) while any CONCLUSION or FIGURE_OR_TABLE is
  STALE_PENDING_REVALIDATION.

## 9. Citations (`citations.py`, `adapters/frozen.py`, `adapters/live.py`)

- **Layer 1, `verification_log`, fully offline.**
  - The input is a log `{claimed_verified: n, verifier: {name, version}, entries: [{citation_id, claimed_status}], invocations: [{invocation_id, citation_id, request, response_sha256, retrieved_at}]}`.
  - An entry claimed as verified with no matching invocation is UNVERIFIED with
    NARRATED_VERIFICATION.
  - A `claimed_verified` greater than the number of invocations breaks
    `checked_claims_le_invocations`.
  - Eight claimed verifications with zero invocations → ABSTAIN / UNVERIFIED,
    exit 2.
- **Layer 2, `citation_resolver`, frozen.**
  - Each frozen record carries `retrieved_at, request_url_or_query, response_sha256, resolver_identity, resolver_schema_version, live_refresh_performed`, together with the minimum metadata permitted.
  - A missing provenance field makes that record's state SOURCE_UNAVAILABLE.
  - Per-DOI states come from `ResolverState`.
  - With live mode off, anything missing from the frozen set is
    SOURCE_UNAVAILABLE, never "not found".
- **Layer 3, `citation_metadata`.**
  - Compares title (casefolded, whitespace and punctuation normalized), authors
    and their order, year, journal, volume, issue, and DOI-to-work consistency.
  - CONFLATED_ENTRY applies when the fields match two different frozen records.
  - Each citation gets exactly one `primary_disposition` plus a list of
    `defects`, which may overlap.
  - Totals are per defect type and are not mutually exclusive.
  - An unresolved replacement candidate is never chosen as ground truth.
- **Live adapter.**
  - It runs only with `--live` or the manifest's `citations.live: true`, uses
    `urllib`, a 10-second timeout, and a `User-Agent` header.
  - Any network error or non-2xx response becomes SOURCE_UNAVAILABLE.
  - Responses are hashed. Only the minimum metadata is stored, and bodies are
    not persisted unless `redistribution_allowed`.
  - Tests inject a failing opener and never touch the network.

## 10. Mutation testing (`mutations.py`)

`mutate(manifest) -> MutationReport` works as follows:

1. **Baseline.** Copy the manifest's tree into a temporary workspace and run
   `verify`. The status must be PASS. Otherwise the report is
   `INVALID_BASELINE`, contains **no** sensitivity figure, omits the count
   keys entirely, and prints "No sensitivity figure was produced because the
   verifier failed its accepting baseline.", exiting 1.
2. **Mutations.** For each operator, check applicability. An operator with no
   target is NOT_APPLICABLE. Otherwise apply it to a fresh copy and run verify.
   The mutation counts as **detected** only if the status is not PASS **and**
   the expected detecting invariant or check fired. Otherwise it is
   **escaped**, reported as `BLIND_SPOT`.
3. **Report records.** Each mutation records `mutation_id, description,
   expected_result, actual_result, applicable, execution_state,
   expected_detector, detecting_invariants_fired, detected, blind_spot,
   diagnostics`.
4. **Counts.** The report counts `applicable_mutations`,
   `executed_mutations`, `detected_mutations`, `escaped_mutations`,
   `skipped_mutations` and `not_applicable_mutations`. Sensitivity is
   `detected/executed`, as an exact fraction string plus a decimal string, and
   only when `executed > 0` and the baseline is valid. With zero executed there
   is no figure, and the result is ABSTAIN.

Required operators, with stable ids:

- `M01_empty_input`
- `M02_missing_expected_file`
- `M03_deleted_accepted_row`
- `M04_duplicate_row`
- `M05_duplicate_reviewer_verdict`
- `M06_missing_required_reviewer`
- `M07_changed_source_hash`
- `M08_changed_author`
- `M09_changed_doi`
- `M10_changed_numeric_value`
- `M11_changed_numeric_formatting`
- `M12_timezone_shift`
- `M13_removed_invocation`
- `M14_pass_summary_without_evidence`
- `M15_skipped_required_checker`
- `M16_truncated_ledger`
- `M17_reordered_hash_chain`
- `M18_changed_upstream_design`
- `M19_replaced_stored_claim_output`
- `M20_metadata_change_under_unchanged_pass_summary`

M16 and M17 act on a recorded ledger. Their detector is
`Ledger.verify_chain`, run by the `ledger_chain_intact` invariant, which
receives a previously sealed run through the mutation harness.

## 11. Receipts (`receipts.py`)

The canonical JSON is:

- UTF-8, with keys sorted
- separators `(",", ":")` and `ensure_ascii=False`
- integers only (other numbers as strings), with no NaN and no floats

The receipt body is:

```json
{"schema":"science-gate-receipt/v1","subject":[{"name":"<input id or path>","digest":{"sha256":"…"}}],
 "predicate_type":"science-gate/run/v1","predicate":{…run summary incl. status, reason, counters,
 ledger_head_sha256, ledger_length, evidence_manifest_sha256, tool {name, version}…},
 "evidence_boundary":{"integrity":"…","performance":"…","scientific_validity":"NOT ESTABLISHED"},
 "disclaimer":"A receipt supports integrity, provenance, and replayability. It does not establish scientific truth, accuracy, safety, or fitness for use."}
```

The receipt file wraps that body:

```json
{"body": {…}, "content_sha256": "sha256(canonical(body))", "signature_state": "UNSIGNED", "signature": null, "key_id": null}
```

Signing:

- When `SCIENCE_GATE_HMAC_KEY_FILE` points to a readable key file, the receipt
  is signed with HMAC-SHA256 over the canonical body. `signature_state` becomes
  `SIGNED_HMAC_SHA256` and `key_id` is the sha256 of the key. The key itself is
  never output.
- In every other case the receipt is UNSIGNED, with `signature: null`.
- `verify_receipt(path)` recomputes the content hash.

Any change to protected content changes `content_sha256`.

## 12. Reports (`reports.py`)

`verify` writes to `--output RUN_DIR` (default `./science-gate-runs/<run_id>/`) using only safe writes:

| file | content |
|---|---|
| `run.json` | machine-readable RunResult with the PASS contract fields at top level |
| `report.md` | human report. Its first headings are, in order: `STATUS`, `WHAT WAS EXPECTED`, `WHAT WAS EXAMINED`, `WHAT ACTUALLY RAN`, `WHAT PASSED`, `WHAT FAILED`, `WHAT ABSTAINED`, `WHAT REMAINS UNRESOLVED`, `WHAT THIS RESULT DOES NOT PROVE` |
| `ledger.jsonl` | the execution ledger |
| `evidence-manifest.json` | one entry per piece of evidence, with its sha256 |
| `receipt.json` | the run receipt (the bare statement, 17.9) |
| `receipt.auth.json` | the receipt's authentication sidecar (17.9) |
| `results.sarif` | SARIF 2.1.0 |
| `report.html` | self-contained dashboard (see below) |

`science-gate report RUN_DIR` re-reads a run directory, re-verifies the
receipt and the ledger chain, and re-renders `report.md` and `report.html`. If
either fails verification, the report says so, with status ERROR and exit 3.

`report.html` is the **evidence-boundary hologram**:

- It is one self-contained file. It has no external requests, scripts or fonts.
- Colors are CSS variables, with a light and a dark theme.
- Three stacked translucent planes show Integrity, Performance, and Scientific
  Validity. Each plane is lit only by the evidence that exists for it.
  Scientific Validity is always drawn dark and labeled "not established by
  this tool".
- Around the planes it shows:
  - the input-accounting funnel: expected → discovered → opened → parsed → examined, with closure state
  - the check lattice: expected vs executed vs terminal, each cell a check with its state
  - an invariant ring
  - a ledger chain strip, with the hash head
  - for mutation runs, a detected-versus-blind-spot constellation
- Every visual element has a text equivalent in the page, for accessibility and
  so the page can be diffed.

## 13. Packaging (`packaging.py`, `science-gate package MANIFEST --output PATH`)

The package contains:

- `package.json`, holding the access class, the permissions, the source
  licenses as declared, the hashes of every input, the expected results, the
  approved redactions, and local execution instructions
- the schemas
- the expected results

Data files are included only when both hold:

- the access class is `PUBLIC` or `SYNTHETIC`
- `redistribution_allowed` is true, or the class is `SYNTHETIC` with its
  default synthetic permissions

`CONTROLLED_LOCAL` and `REFERENCE_ONLY` inputs are **never** copied; only
their hashes and retrieval instructions are included.

Other rules:

- It is stated explicitly that evaluation permission does not imply training
  permission.
- Output goes only inside `--output`. An output path inside any input
  directory is refused.
- Existing output is refused unless `--force`.

## 14. CLI (`cli.py`)

The subcommands are:

- `init PATH`
- `verify MANIFEST [--output DIR] [--live]`
- `report RUN_DIR`
- `mutate MANIFEST [--output DIR]`
- `impact ARTIFACT_ID --manifest MANIFEST`
- `revalidate ARTIFACT_ID --manifest MANIFEST`
- `package MANIFEST --output PATH [--force]`
- `demo [--output DIR]`

Exit codes follow `Status`: 0, 1, 2 or 3. Argument errors exit 3 with a
message, not argparse's 2, so that 2 always means ABSTAIN. Every command
prints a one-line status headline first, then the paths it wrote.

## 15. Security (tests in `tests/test_security.py`)

- path traversal
- symlink escape (skipped with a visible reason where symlinks cannot be created)
- duplicate manifest paths
- oversized input
- unexpected file count
- malformed JSON
- hash mismatch
- unsafe subprocess request keys
- secret leakage: a fake token planted in the environment and in an input must
  never appear in any output file, because values matching secret patterns are
  redacted
- writes outside the output directory

## 16. Tests

- The framework is `unittest` (stdlib). Run the suite with
  `python -m unittest discover -s tests -v`.
- `tests/test_required.py` contains one test per numbered requirement, 1–28,
  named `test_rNN_…`.
- Determinism is tested by running the CLI twice, with `PYTHONHASHSEED=0` and
  `PYTHONHASHSEED=4242` and a fixed clock, and comparing the output
  byte-for-byte.
- `tests/test_security.py` covers section 15, and `tests/test_determinism.py`
  applies the two-seed comparison to `verify`, `report`, `mutate`,
  `package`, `impact` and `revalidate`. The demo (18.11) is its own
  acceptance test.

## 17. Frontier extensions

This section binds the frontier build (still version 0.1.0, unreleased). It adds extensions #1–#13, #15, #16, #17,
#22, #23 and #24 of the research brief
(`reports/research/leaders-and-patterns.md`, sections 5.2 and 5.3) and
decisions D1–D12 (its section 6). Extensions #14, #18–#21 and #25–#31 are
deferred and must not be built. Where this section disagrees with sections
0–16 or 18, this section wins, and 17.2 names each rule it supersedes. The
0.1.0 decision record is now section 18 (18.1–18.11, formerly 17.1–17.11).

Unchanged: stdlib only; no subprocess (the audit hook of 17.6 is the only
process-wide hook); deterministic output; no network in tested paths; exit
codes 0/1/2/3 keep their meanings; requirements 1–28 hold; missing evidence
never becomes PASS. Strengthened: a PASS must carry a witness that its
checker could have failed (17.5). Every new identifier is a prefix plus hex of
a SHA-256 over content (D11). Implementations re-derive every idea from the
brief's description; no third-party code or text is copied.

### 17.1 Build-stage file ownership

Builders may edit ONLY their files; anything else goes to `requests_for_shared_files`.

- engine: src/science_gate/models.py (after you), verifier.py, ledger.py, invariants.py, _audit.py (new: the single gated audit hook used by #9 and #11); fixtures/core/**; tests/test_models.py, test_verifier.py, test_ledger.py, test_invariants.py, test_falsifiers.py, test_plan.py, test_harness_pin.py, test_verdict_lattice.py. Extensions #1 #2 #9 #23 #24, D1 D2 D11.
- integrity: receipts.py, _canonical.py, cli.py; tests/test_receipts.py, test_canonical.py, test_cli.py, test_receipt_auth.py, test_canonical_vectors.py. Extensions #15 #16, D8 D9.
- reports: reports.py, _validators.py (new); fixtures/exporters/**; tests/test_reports.py, test_exporter_validators.py. Extension #12, D7.
- numeric: numeric.py (new), claims.py; fixtures/numeric/**, fixtures/claims/**; tests/test_claims.py, test_numeric_forensics.py, test_narrated_numbers.py, test_numeric_coverage.py. Extensions #3 #7 #17, D5.
- mutations: mutations.py; fixtures/mutations/**; tests/test_mutations.py, test_mutation_accounting.py, test_activation.py, test_harness_mutation.py. Extensions #4 #11 #13 (+ operator M21_removed_plan), D12.
- dependencies: dependencies.py; fixtures/dependencies/**; tests/test_dependencies.py, test_witnessed_revalidation.py, test_staleness_whatif.py. Extensions #5 #22, D6.
- citations: citations.py, adapters/**; fixtures/citations/**; tests/test_citations.py, test_resolver_controls.py, test_editorial_status.py. Extensions #8 #10.
- assertions: assertions.py (new); fixtures/assertions/**; tests/test_claim_join.py. Extension #6.

Residual owners: the engine also owns G1–G3 (17.7), the reports builder G4
and G5 (17.10), the integrity builder D3, D4 and the CLI (17.9), and the
engine D10 (the mutations builder consumes the hook).

Everything else is unowned: `manifests.py`, `discovery.py`, `_safeio.py`,
`_clock.py`, `_redact.py`, `_resources.py`, `_html.py`, `packaging.py`,
`demo.py`, `schemas/*.json`, `fixtures/packaging/**`, `examples/**`, the
top-level documents, `tests/_helpers.py`, `tests/_project.py`, and every test
module not listed above. Those change only through
`requests_for_shared_files`, applied at integration (17.18). A builder whose
parser gains keys states the exact schema edit as a request; its
schema-consistency test may then be red until integration, and it says so
under known gaps. This section adds no manifest key: all new evidence
arrives as declared inputs, check `params`, or fields of existing documents,
so `manifests.py` does not change.

### 17.2 Decisions D1–D12

| # | Resolution | Supersedes | Owner |
|---|---|---|---|
| D1 | A required planned check that did not execute (no terminal invocation, or SKIPPED/NOT_APPLICABLE without a `SkipJustification`) is FAIL / PARTIAL_EXECUTION. A justified one contributes its row of `SKIP_JUSTIFICATION_OUTCOMES` (always ABSTAIN, never PARTIAL_EXECUTION). Inputs are untouched: a PARTIAL input stays ABSTAIN / PARTIAL_EXECUTION (requirement 7). | §6 "ABSTAIN — … skipped"; 18.3 `contract:checks_executed` as ABSTAIN | engine |
| D2 | BLIND_SPOT is also a check and run reason. It is FAIL when a miss is proven (a falsifier or canary accepted known-bad input, the comparator called unequal values equal, a resolver canary resolved) and ABSTAIN when coverage is unknown (no witness, an unpinned file, a missing resolver canary). | §10 (BLIND_SPOT as a mutation-report reason only) | engine; citations for #8 |
| D3 | Exit codes unchanged: 0 PASS, 1 FAIL, 2 ABSTAIN, 3 ERROR and usage errors. A failed `--require-signature` exits 3 (17.9). Anything that later ingests a test runner's "no tests collected" (pytest or unittest exit 5) maps it to ABSTAIN, never PASS; nothing ingests one in this stage. | nothing | integrity |
| D4 | The three plane names stay. The receipt's `performance` statement is two labelled parts: `CHECKER:` (falsifier witnesses, canary, comparator self-test) then `RUN:` (the check tally). | §11 performance text | integrity |
| D5 | Half-even stays the rule for the project's own outputs (`numeric_agreement`, stored claim outputs). A registered claim with `"rounding": "EITHER_HALF"` (a third-party number) agrees when half-even or half-up reproduces it, and the convention set is recorded. | §7 half-even-only agreement, for claims marked EITHER_HALF | numeric |
| D6 | Revalidating a derived node (one with at least one parent) as unchanged needs a recompute witness (17.13). Re-hashing alone is refused as VACUOUS_CUTOFF. A root node of any kind revalidates by re-hash as in §8, which keeps requirement 20. | §8 `revalidate` for derived nodes | dependencies |
| D7 | A SARIF log of an ERROR run sets `invocations[0].executionSuccessful` to false and carries a toolExecutionNotification; validated (17.10). | §1 SARIF alignment (adds the flag) | reports |
| D8 | Canonical JSON never claims RFC 8785: keys sort by Unicode code point, not UTF-16 code unit. Integers outside ±(2^53 − 1) are refused. Golden vectors pin both. | §11 (adds the integer bound) | integrity |
| D9 | No file is ever an envelope with an empty signature. `receipt.json` is always the bare statement, and authentication lives in the sidecar `receipt.auth.json` (17.9). HMAC is called a shared-key authenticator, never a public signature. | §11 and §12 receipt file; 18.8 | integrity |
| D10 | Everything stays in-process. `science_gate._audit` installs one process-wide `sys.addaudithook` once; it records nothing unless a recording context is active. Subprocess and C-extension I/O are invisible to it, and report.md says so. | §0 (permits the hook) | engine |
| D11 | Every identifier in every export is a content-hash id: `run-`, `inv-`, `mut-`, `har-`, `wif-`, `wit-` and canary nonces. No UUIDs anywhere. | nothing | engine; all builders follow |
| D12 | No mutation time budget is added. TIMED_OUT and FLAKY exist in the closed vocabulary, never count as detections, and nothing produces them in this stage. | nothing | mutations |

The extensions also supersede these older rules:

- §4: the ledger now begins with a PLAN entry whose `invocation_id` is null (17.4).
- §5: "a check with nothing to look at returns NOT_APPLICABLE" now also requires a `SkipJustification` (17.7).
- §6: a PASS additionally needs every PASS result WITNESSED and the six new invariants holding (17.5, 17.6).
- 18.2 and 18.3: the per-check rows total and the "standalone" rows term give way to G1 (17.7).
- §9: resolution goes by body codes and needs per-prefix canaries (17.14).
- §10 and 18.7: the operator list gains M21 and the M00 control; `escaped_mutations` = executed − detected; M15's detector is a FAIL (17.12).
- §11, §12 and 18.8–18.9: the receipt is a statement plus sidecar; run directories gain `receipt.auth.json`, atomic finalization and validators (17.9, 17.10).
- §14: the CLI gains `what-if` and the new flags (17.9).

### 17.3 Vocabulary (`models.py`)

Delivered by the amendment stage and tested in `tests/test_models.py`; the
engine owns the file from the build stage on.

- `Reason` += `PROTOCOL_DRIFT`, `HARNESS_BLIND`, `UNMEASURED_MUTANTS`. `FailureMode` += `VACUOUS_CUTOFF`.
- New enums: `AuthStatus` (UNSIGNED, SIGNED_VERIFIED, SIGNED_FAILED, SIGNED_UNCHECKED); `SkipJustification` (EMPTY_POPULATION, INPUT_UNAVAILABLE, SOURCE_REJECTED, EVIDENCE_MALFORMED, NOT_DECLARED, NO_DISCRIMINATION, GUARDED_ELSEWHERE); `FalsifierOutcome` (REJECTED, ACCEPTED, INCONCLUSIVE); `WitnessState` (WITNESSED, REFUTED, UNWITNESSED, NO_CASE, NO_GENERATOR); `NumericOutcome` (CONSISTENT, INCONSISTENT, VACUOUSLY_CONSISTENT, NOT_TESTABLE); `RoundingConvention` (HALF_EVEN, HALF_UP, TRUNCATE, CEILING, FLOOR, FLOAT_FIRST); `MutationStatus` (DETECTED, BLIND_SPOT, VERIFIER_ERROR, TIMED_OUT, FLAKY, NOT_ACTIVATED, NOOP_MUTATION, CANONICALLY_EQUIVALENT, DUPLICATE_MUTANT, SUPPRESSED, SKIPPED, NOT_APPLICABLE); `PieStage` (NOT_READ, READ_NOT_INFECTED, INFECTED_NOT_PROPAGATED, PROPAGATED_NOT_CHECKED); `AssertionKind` (TESTS_RUN, COMMAND_EXECUTED, FILE_CHECKED, DATASET_VALIDATED, TOOL_CALL); `AssertionOutcome` (BACKED, NARRATED, CONTRADICTED, ORPHANED); `EditorialStatus` (NOT_RETRACTED_WITHIN_SCOPE, RETRACTED, REINSTATED, CORRECTED, EXPRESSION_OF_CONCERN, UNDETERMINED); `NoticeType` (RETRACTION, REINSTATEMENT, CORRECTION, EXPRESSION_OF_CONCERN); `EditorialChannel` (CROSSREF_UPDATED_BY, CROSSREF_RETRACTION_WATCH, RETRACTION_WATCH_SNAPSHOT); `StaleCause` (UPSTREAM, VERIFIER); `RatioState` (DEFINED, ZERO_DENOMINATOR, UNAVAILABLE); `VerdictLevel` (NONE < PASS < ABSTAIN < FAIL < ERROR).
- Tables: `SKIP_JUSTIFICATION_KEY` (`"skip_justification"`), `SKIP_JUSTIFICATION_OUTCOMES`, `UNJUSTIFIED_SHORTFALL_OUTCOME` (FAIL / PARTIAL_EXECUTION), `FALSIFICATION_OUTCOMES`, `REJECTION_REASONS`, `NUMERIC_OUTCOME_VERDICTS`, `EITHER_HALF`, `EXECUTED_MUTATION_STATUSES`, `COUNTS_AS_DETECTED`, `EMPTY_AGGREGATE_OUTCOME` (ABSTAIN / INSUFFICIENT_EVIDENCE).
- Lattice: `verdict_level(status)`, `join_verdicts(levels) -> VerdictLevel` (NONE for nothing), `VerdictTransition(step, source, before, after, reason)` (must rise), `fold_verdicts(contributions) -> (VerdictLevel, tuple[VerdictTransition, ...])` over `(source, status, reason)` triples.
- `Ratio(numerator: int|None, denominator: int|None)`: a proportion (0 ≤ n ≤ d). `state`; `value` (exact `Fraction`, None unless DEFINED); `fraction` (`"n/d"` as counted, never reduced); `decimal` (ROUND_HALF_EVEN to 4 places, trailing zeros removed: `"0.72"`, `"0"`, `"1"`; None unless DEFINED); `exact`; `to_dict()` = `{numerator, denominator, state, fraction, decimal, exact}`. Thresholds compare `value`, never `decimal`. A zero denominator has no value and no decimal.
- `InputOverride(rows, columns=None)` and `FalsifierCase(case_id, description, expected_verdict, expected_reason, inputs={}, documents={})`: see 17.5.
- The engine adds `claim_join`, `editorial_status` and `mutation_accounting` to `BUILTIN_CHECK_KINDS` in the same change that registers them (17.16); adding them earlier would break the registry-equals-kinds test.

### 17.4 PLAN entry and plan invariants (#2; engine)

Every `verify` ledger starts with one PLAN entry, hash-chained before the
first STARTED entry. The brief's "seq 0" is the first entry: `seq` stays
1-based, so the PLAN is seq 1. It has exactly `ENTRY_FIELDS`:
`seq` 1, `invocation_id` null, `check_id` null, `check_kind` `"PLAN"`,
`check_version` `"science-gate-plan/v1"`, `input_ids` (every declared input
id, sorted), `input_sha256s` (`{id: declared sha256 or null}`), `started_at`
now, `completed_at` null, `result` `"PLAN"`, `evidence` = the plan body,
`verdict` null, `reason` null, `prev_entry_sha256` genesis. Plan body:

```json
{"schema": "science-gate-plan/v1", "run_id": "run-…", "manifest_sha256": "…",
 "tool": {"name": "scientific-evidence-gate", "version": "…"},
 "inputs": [{"input_id": "…", "required": true, "format": "csv", "declared_sha256": "…|null",
             "row_key": ["…"], "expected_rows": 12, "denominator_source": "INDEPENDENT"}],
 "checks": [{"check_id": "…", "kind": "…", "version": "…", "required": true, "inputs": ["…"],
             "params_sha256": "…", "checker_sha256": "…"}],
 "pins": [{"role": "manifest|input|document|check_module", "path": "…", "sha256": "…|null"}],
 "controls": ["control:canary:must_fail", "control:canary:must_pass", "control:comparator"]}
```

Lists sort by id, pins by `(role, path)`. Formulas every module uses:
`params_sha256 = sha256_canonical(dict(spec.params))`;
`checker_sha256 = sha256_canonical({"target": "<module:function>", "module_sha256": <sha256 of the module source file found by importlib.util.find_spec(module).origin, or null>})`.

`ledger.py` adds `PLAN_RESULT = "PLAN"`, `PLAN_KIND = "PLAN"`,
`PLAN_SCHEMA = "science-gate-plan/v1"`, and:

- `Ledger.plan(body: Mapping[str, Any]) -> dict[str, Any]`: appends the PLAN; `LedgerError` unless the ledger is empty.
- `is_plan_entry(entry: Mapping[str, Any]) -> bool`.
- `plan_of(entries: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None`: the body of entry 1 when it is the only PLAN entry.
- `reseal(entries: Sequence[Mapping[str, Any]], run_id: str) -> ResealResult` with fields `entries`, `ledger_head_sha256`, `ledger_length`, `invocation_ids` (old id → new id). It renumbers `seq`, re-derives every STARTED id (and its terminal's) from `run_id`, and re-links and re-hashes: what a thorough forger would do.
- `verify_chain` and `index_invocations` are unchanged; the PLAN has no invocation id.

`verifier.build_plan(manifest, accounting, pins, run_id, registry) -> dict[str, Any]`
builds the body. Six invariants are appended to `INVARIANT_NAMES`, in this
order: `plan_closure`, `plan_matches_manifest`, `harness_pins_intact`,
`comparator_self_test`, `canary_controls_hold`,
`pass_requires_falsifier_witness`. The first two:

- `plan_closure` (applicable when the ledger has an entry): holds iff entry 1 is a PLAN, no later entry is, and every planned `check_id` and every planned control (the PLAN's `controls` list) has exactly one terminal invocation (D1: an unexecuted planned item is a failure). Falsifier invocations are never unplanned. Unplanned non-control invocations are listed in the detail, not judged. The detail names each offending `check_id`. Violation: FAIL / PARTIAL_EXECUTION / PARTIAL_EXECUTION.
- `plan_matches_manifest` (applicable when a PLAN exists and `DecisionInputs.expected_plan` is set): holds iff the recorded body equals `expected_plan` canonically. Violation: FAIL / PROTOCOL_DRIFT / PROTOCOL_DRIFT.

`DecisionInputs` and `InvariantContext` gain `expected_plan`, `pins` (17.6),
`controls` (17.5, 17.6) and `rows_examined` (17.7), all optional, so a
sealed run can be replayed through `decide()`.

### 17.5 Falsifier witnesses and the canary (#1; engine)

`verifier.FALSIFIERS: Mapping[str, str]` maps each kind to a lazily imported
generator `def falsify_<x>(ctx: CheckContext, spec: CheckSpec, result: CheckResult) -> tuple[FalsifierCase, ...]`.
A generator is deterministic, reads only through `ctx`, writes nothing, and
returns `()` when this instance admits no known-bad case. A missing or
unimportable target means NO_GENERATOR. Names:

| kind | generator | case built (`case_id`) | expected rejection |
|---|---|---|---|
| row_count | `science_gate.verifier:falsify_row_count` | `drop-last-row`: last admitted row of each input with an INDEPENDENT `expected_rows` removed | FAIL / SOURCE_MISMATCH |
| required_columns | `science_gate.verifier:falsify_required_columns` | `drop-column`: first declared column removed from the header and every row | FAIL / SOURCE_MISMATCH |
| duplicate_rows | `science_gate.verifier:falsify_duplicate_rows` | `duplicate-first-row`: a copy of the first admitted row appended | FAIL / SOURCE_MISMATCH |
| snapshot_completeness | `science_gate.verifier:falsify_snapshot_completeness` | `delete-accepted-row`: first admitted row the snapshot accepts removed | FAIL / SOURCE_MISMATCH |
| numeric_agreement | `science_gate.verifier:falsify_numeric_agreement` | `shift-stored-value`: stored cell of the first compared row set to claim + 10^-d (d = printed decimals), printed with d decimals and no grouping | FAIL / SOURCE_MISMATCH |
| reviewer_protocol | `science_gate.verifier:falsify_reviewer_protocol` | `drop-required-reviewer`: every verdict of the first required reviewer removed | ABSTAIN / PROTOCOL_BROKEN |
| time_source | `science_gate.verifier:falsify_time_source` | `shift-utc`: one hour added to the first event's `utc` | FAIL / SOURCE_MISMATCH |
| summary_consistency | `science_gate.verifier:falsify_summary_consistency` | `alter-pinned-digest`: first pinned input digest (else document digest) replaced | FAIL / SOURCE_MISMATCH |
| verification_log | `science_gate.citations:falsify_verification_log` | invocation backing the first VERIFIED entry removed | ABSTAIN / UNVERIFIED |
| citation_resolver | `science_gate.citations:falsify_resolver` | first resolved DOI's record replaced by a captured NOT_FOUND | FAIL / SOURCE_MISMATCH |
| citation_metadata | `science_gate.citations:falsify_metadata` | first author of the first citation replaced | FAIL / SOURCE_MISMATCH |
| editorial_status | `science_gate.citations:falsify_editorial_status` | a RETRACTION notice added for the first cited DOI | FAIL / SOURCE_MISMATCH |
| claim_registry | `science_gate.claims:falsify_claim_registry` | first resolved claim's stored value changed at its printed precision | FAIL / SOURCE_MISMATCH |
| dependency_currency | `science_gate.dependencies:falsify_dependency_currency` | a publication node's file digest changed in the overlay | FAIL / SOURCE_MISMATCH |
| claim_join | `science_gate.assertions:falsify_claim_join` | first BACKED assertion's `claimed_result` flipped | FAIL / SOURCE_MISMATCH |
| mutation_accounting | `science_gate.mutations:falsify_mutation_accounting` | one id removed from the first non-empty bucket | FAIL / UNMEASURED_MUTANTS |

`models.FalsifierCase` is data only: `case_id` (`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`),
`description`, an expected rejection allowed by `REJECTION_REASONS` (FAIL with
any reason but VERIFIED; ABSTAIN only with UNVERIFIED, PROTOCOL_BROKEN,
REQUIRES_HUMAN_REVIEW, SOURCE_MISMATCH or PROTOCOL_DRIFT), `inputs`
(`{input_id: InputOverride(rows, columns=None)}`, replacement admitted
records) and `documents` (`{manifest-relative path: replacement bytes}`, keys
normalized), at least one of them non-empty. This amends the brief: a
falsifier must provoke its kind's declared rejection, which for
`reviewer_protocol` and `verification_log` is ABSTAIN by §5 and §9.

Engine procedure, inside `_run_one`, for each declared check whose result is PASS:

1. Resolve the generator; none gives NO_GENERATOR. Call it; `()` gives NO_CASE.
2. For each case: `CheckContext.overlay(case) -> CheckContext` builds an in-memory context. Each overridden input becomes an OpenedInput in state PARSED with rows numbered 1..n (line null), counts admitted n and the rest 0, closure re-evaluated against the spec's own `expected_rows` and `denominator_source`, and `sha256 = sha256_canonical(override.to_dict())`. Overridden documents are served through the normal parse rules. Nothing touches disk. The same function runs with the same `spec` through the same result builder, inside its own invocation `control:falsifier:<check_id>:<case_id>` (subject's kind, version and input ids; overridden inputs carry their overlay digests).
3. Outcome per case: REJECTED iff `(verdict, reason)` equals the expectation; ACCEPTED iff PASS; else INCONCLUSIVE.
4. State: REFUTED if any ACCEPTED; else WITNESSED if any REJECTED; else UNWITNESSED.
5. Unless WITNESSED, the subject becomes `FALSIFICATION_OUTCOMES[state]` (status, reason, and failure modes added) with diagnostic `FALSIFIER_<STATE>: …`, before its terminal entry is written.

Ledger order is subject STARTED, then each falsifier's STARTED and terminal,
then the subject's terminal. Controls never get falsifiers. Evidence added to
the subject's `CheckResult.evidence`: `falsification` (WitnessState value),
`checker_sha256`, `params_sha256`, and `falsifiers`, a list of
`{case_id, description, control_id, checker_sha256, params_sha256, expected: {verdict, reason}, actual: {verdict, reason, execution_state}, outcome}`, where `control_id` is the ledger check id `control:falsifier:<check_id>:<case_id>`. Invocation ids derive from the run id, which includes the start time, so embedding them would make every evidence digest change from day to day (18.10); the ledger binds the witness instead, through the falsifier terminal's `subject_invocation_id`.
A falsifier's terminal ledger evidence is `{control: "falsifier", subject_check_id, subject_invocation_id, case: case.to_dict(), checker_sha256, params_sha256, outcome}`.

`pass_requires_falsifier_witness` (applicable when any result is PASS):
holds iff every PASS result has `falsification` WITNESSED and at least one
REJECTED falsifier whose invocation is terminal in the ledger under
`control:falsifier:<check_id>:<case_id>`, with the recorded verdict and
reason, and digests equal to the subject's. Violation: ABSTAIN / BLIND_SPOT /
VACUOUS_PASS. It catches a narrated witness in a replayed or re-read run.

Canary: after the last declared check, the engine runs
`control:canary:must_fail` and `control:canary:must_pass`, both
`verifier.check_duplicate_rows` (called directly, never via the registry)
with kind `duplicate_rows` and version `"1"`, over an in-memory CSV input
`control-canary` with columns `id,value`. must_fail has rows `c1,1` twice and
expects FAIL; must_pass has `c1,1` and `c2,2` and expects PASS. Both pass
through the same result builder and ledger as every check, and neither
appears in `RunResult.checks`. `canary_controls_hold` holds iff both ended as
expected; violation: FAIL / BLIND_SPOT / DEFECTIVE_VERIFICATION.

### 17.6 Harness pins, the audit hook and the comparator self-test (#9, D10; engine)

`science_gate._audit` (new):

- `install() -> None`: idempotent; adds the one process hook.
- `recording(*, watch: Iterable[str | os.PathLike] = (), under: Iterable[str | os.PathLike] = (), record_values: bool = False) -> ContextManager[AuditRecorder]`: nestable, held in a `ContextVar`; every active recorder sees the events that match its filters. Paths are resolved, absolute and `os.path.normcase`d. `watch` names files and `under` names directory prefixes.
- `FileEvent(path: str, action: "read"|"write"|"delete"|"rename", event: str)`. Audit events `open` (a write when the mode holds `w`, `a`, `x` or `+`, or the flags hold O_WRONLY, O_RDWR, O_APPEND, O_CREAT or O_TRUNC), `os.remove`, `os.rename` (source and destination), `os.truncate`, `shutil.copyfile` (destination) and `shutil.rmtree`.
- `AuditRecorder.events`, `.writes` (non-read events) and `.value_reads`, a tuple of `ValueRead(check_id, input_id, row_index, column)`.
- `current_check(check_id: str | None) -> ContextManager[None]`, set by the engine around each check and control. `RecordingMapping`: a read-only `Mapping` that reports each key read to recorders with `record_values`.

Pins: before the PLAN, the engine hashes the manifest, every declared input,
every file in the context's read log (role documents and preloaded files),
and the source file of every module named by `REGISTRY` or `FALSIFIERS` for a
declared kind, plus `science_gate.verifier` itself. Paths are
manifest-relative; modules are named by module name. Checks, falsifiers and
controls run inside `_audit.recording(watch=<pinned paths>)`. After the last
control, every pin is re-hashed from disk (missing gives null).
`DecisionInputs.pins` is `{"pinned": [{role, path, sha256, sha256_after}], "writes": [{path, action, event}], "hook_errors": n}`, where `hook_errors` counts audit events the hook could not interpret.
`harness_pins_intact` holds iff every re-hash equals its pin, the pins equal
those the PLAN committed to, `hook_errors` is 0, and no write, delete or
rename touched a pinned path, even if the bytes were restored.
Violation: FAIL / PROTOCOL_DRIFT / PROTOCOL_DRIFT, with the detail naming each
path. While a recorder with `record_values` is active, the engine gives each
check CSV rows whose values are `RecordingMapping`s (used by 17.12).

Comparator self-test: once per run, after the checks, invocation
`control:comparator` (kind `comparator_self_test`, version `"1"`) compares
three pairs through the attribute `science_gate.invariants.compare_decimal`,
looked up at call time: claim `"0.15"` vs stored `"0.14"` must be DISAGREES,
`"12.4"` vs `"12.40"` EXACT, and `"0.1"` vs `"0.14"`
AGREES_AT_STATED_PRECISION. Its verdict is PASS / VERIFIED iff all three hold,
else FAIL / BLIND_SPOT. `numeric_agreement` and `claims.py` must call the
comparator the same way (module attribute, not a bound import), so a patched
comparator is the one both use. `comparator_self_test` holds iff the control
held; violation: FAIL / BLIND_SPOT / DEFECTIVE_VERIFICATION.

Control order after the last declared check: comparator, then canary
must_fail, then canary must_pass. `RunResult.checks` and the check counters
never include controls.

### 17.7 Skips, the lattice and `decide()` (#23, #24, D1, D2, G1–G3; engine)

Justifications travel in `CheckOutcome.evidence[SKIP_JUSTIFICATION_KEY]` as
a `SkipJustification` value, so they are hashed with the evidence and need no
new field. `_result_from` refuses, as ERRORED `INVALID_OUTCOME`, a label that
is not a member, or a label on a result that is not SKIPPED or NOT_APPLICABLE
with verdict ABSTAIN. Engine helpers label their returns:
`Findings.not_applicable(reason, detail, evidence, *, justification)` (keyword
now required); `_no_rows_to_examine` gives NOT_DECLARED with no inputs,
SOURCE_REJECTED for a HASH_MISMATCH input, INPUT_UNAVAILABLE for MISSING,
REFUSED, OPEN_FAILED or PARSE_ERROR, and EMPTY_POPULATION for EMPTY or for a
usable input with zero admitted rows; `document_unavailable` gives
INPUT_UNAVAILABLE (EVIDENCE_MALFORMED for PARSE_ERROR); `malformed_document`
gives EVIDENCE_MALFORMED; "the manifest declares no …" and "the stored
summary claims …, not PASS" give NOT_DECLARED; "no events" gives
EMPTY_POPULATION. Specialists label their own skip helpers the same way
(`citations._not_applicable`, the claims verdict helper,
`dependencies._unexamined`).

G1, population: run-level `rows_examined` is the number of distinct admitted
data rows of declared inputs consumed by at least one CHECKED check.
Comparisons, pins, verdicts, events, citations and claims are never rows; the
0.1.0 "standalone" term is removed. A check's own `rows_examined` still counts
its subject records and is never summed into the run figure.
`pass_requires_examined_rows` judges the run against
`InvariantContext.rows_examined`, with detail `rows_examined=N (distinct data rows of declared inputs)`.
A header-only CSV therefore gives `rows_examined` 0, and the PASS contract's
zero-rows rule fires.

G2, shortfall (`contract:checks_executed`): one finding per required check
that is not executed (CHECKED with a terminal invocation), in check-id order.
A result whose verdict is ERROR adds no contract finding, since its own ERROR
decides. A SKIPPED or NOT_APPLICABLE result with label L gives
`SKIP_JUSTIFICATION_OUTCOMES[L]` (for example EMPTY_POPULATION: ABSTAIN /
INSUFFICIENT_EVIDENCE / VACUOUS_PASS, never PARTIAL_EXECUTION). Anything else,
including no result, no terminal invocation or no label, gives
`UNJUSTIFIED_SHORTFALL_OUTCOME` (FAIL / PARTIAL_EXECUTION). Corpus entries
re-baseline accordingly: vacuous-pass is ABSTAIN / INSUFFICIENT_EVIDENCE with
VACUOUS_PASS; coverage-debt (a required check NOT_APPLICABLE as NOT_DECLARED)
is ABSTAIN / OUT_OF_SCOPE; partial-execution (an unlabelled skip) is
FAIL / PARTIAL_EXECUTION. New counters: `checks_justified` and
`checks_shortfall` (required checks not executed with or without a label,
ERROR excluded) and `control_invocations`; each is None when unknown.

Findings are gathered in this order: manifest; inputs; checks (by check id);
contract (`inputs_opened`, `rows_examined`, `checks_expected`, the
`checks_executed` findings, `evidence_manifest`); invariants (in
`INVARIANT_NAMES` order).

`decide()` precedence:

1. **Status** is the lattice join (#23). `fold_verdicts` runs over the required checks whose verdict is PASS (source `check:<id>`, in id order), then over every finding in gathering order. A final NONE resolves to `EMPTY_AGGREGATE_OUTCOME`; otherwise the result is ERROR > FAIL > ABSTAIN > PASS, as before.
2. **Primary reason** (G3): the first finding in gathering order at the top status, except that at FAIL a finding whose reason is PARTIAL_EXECUTION counts only when no other FAIL finding exists (the vacuity order FAIL > PARTIAL_EXECUTION > ABSTAIN, mapped onto D1). So a skipped required check gives FAIL / PARTIAL_EXECUTION unless a content FAIL exists, which then names the reason.
3. `reasons` lists every finding's reason in gathering order, de-duplicated; `failure_modes` is the union.
4. BLIND_SPOT follows D2: FAIL only from a proven miss (REFUTED witness, `canary_controls_hold`, `comparator_self_test`, resolver canary resolved); otherwise ABSTAIN.

`Decision` gains `transitions` (the fold's log).

### 17.8 Run-level additions (engine; receipts and reports mirror them)

`RunResult` gains `controls: Mapping[str, Any]` (normalized; `to_dict()`
emits it under `"controls"`, so `run.json` has a top-level `controls`
object) with exactly these keys:

- `plan`: `{entry_sha256, manifest_sha256, checks_planned, inputs_planned, pins}` or null
- `falsifiers`: `{WITNESSED: [ids], REFUTED: [ids], UNWITNESSED: [ids], NO_CASE: [ids], NO_GENERATOR: [ids], invocations: n}`
- `canary`: `{must_fail: {invocation_id, verdict, reason}, must_pass: {…}, holds}` or null
- `comparator_self_test`: `{invocation_id, pairs: [{claim, stored, expected, actual}], holds}` or null
- `pins`: `{pinned: n, changed: [paths], writes: [{path, action, event}], holds}` or null
- `min_discrimination`: `{check_id, discrimination, ratio}` or null: the minimum by exact value over PASS results whose evidence carries `discrimination_ratio` (ties go to the first check id)
- `claim_join`: `{BACKED: n, NARRATED: n, CONTRADICTED: n, ORPHANED: n}` summed over `claim_join` results, or null when none ran
- `verdict_transitions`: `[VerdictTransition.to_dict()]`

A run whose manifest is invalid has every key null except
`verdict_transitions`. The receipt predicate adds
`controls_sha256 = sha256_canonical(run.controls)`, and
`reports.implied_predicate` mirrors it from `document["controls"]`.

Discrimination (the engine part of #3): `invariants.comparison_discrimination(claim, stored, *, thousands=None, decimal_point=".", precision_decimals=None) -> Ratio`
runs the live comparator over the 21 claims c + k·10^-d, for k = −10…10 (d =
the claim's printed decimals), against the stored value, and returns
`Ratio(number that DISAGREE, 21)`. `numeric_agreement` records
`discrimination` per compared entry, and at check level records
`discrimination` (the minimum's decimal) and `discrimination_ratio` (its
`Ratio.to_dict()`). Generic rule in `_refuse_vacuous_pass`: a PASS whose
evidence carries a `discrimination_ratio` that is not DEFINED, or whose
numerator is 0, becomes ABSTAIN / INSUFFICIENT_EVIDENCE with VACUOUS_PASS.
`claim_registry` uses the same two keys (17.11).

### 17.9 Receipts, canonical JSON and the CLI (#15, #16, D3, D4, D8, D9; integrity)

`receipts.py`:

- `STATEMENT_FILE = "receipt.json"`, `AUTH_FILE = "receipt.auth.json"`, `AUTH_SCHEMA = "science-gate-receipt-auth/v1"`.
- `build_run_receipt(...)` keeps its in-memory record `{body, content_sha256, signature_state, signature, key_id}` (requirement 24 reads it). The record is never written as such.
- `receipt_files(record, *, statement_name: str = STATEMENT_FILE) -> dict[str, bytes]` returns the statement (canonical body plus `\n`) and the sidecar, named by replacing `.json` with `.auth.json`. `receipt_bytes(record) -> bytes` is the statement's bytes. `write_receipt(root, relpath, record) -> tuple[Path, Path]` writes both through `safe_write`.
- Sidecar, unsigned: `{schema, statement, content_sha256, signature_state: "UNSIGNED", detail}`, with no `signature` or `key_id` key at all. Signed: `{schema, statement, content_sha256, signature_state: "SIGNED_HMAC_SHA256", algorithm: "HMAC-SHA256", signature, key_id}`. `detail` comes from `KeyResolution.detail` and never quotes key material.
- `verify_receipt(path, *, environ=None, require_signature=False) -> ReceiptVerification`, which gains `auth_status: AuthStatus | None` (also in `to_dict`). Problems: `AUTH_SIDECAR_MISSING`, `AUTH_SIDECAR_MALFORMED`, `CONTENT_HASH_MISMATCH`, `SIGNATURE_MISMATCH` (auth SIGNED_FAILED), `LEGACY_ENVELOPE` (a statement file holding `body`), and `SIGNATURE_REQUIRED` (requested, and the auth status is not SIGNED_VERIFIED). A signature with no matching key is SIGNED_UNCHECKED: not a problem unless a signature is required.
- `_performance_statement` gains the `CHECKER:` and `RUN:` parts (D4); `run_predicate` gains `controls_sha256`.

`_canonical.py`: `MAX_SAFE_INTEGER = 2**53 - 1`. `normalize` and
`strict_loads(…, integers_only=True)` refuse integers outside that bound. Key
order stays by code point (D8). `tests/test_canonical_vectors.py` pins golden
vectors inline: a non-BMP key sorts after U+E000 (where JCS would differ),
duplicate keys are refused, ±2^53 − 1 are accepted and ±2^53 refused, floats
and non-finite values are refused, and the exact output bytes of a fixed
document.

`cli.py` additions (argument errors still exit 3):

- `verify MANIFEST [--output DIR] [--live] [--require-signature]`
- `report RUN_DIR [--require-signature]`
- `mutate MANIFEST [--output DIR] [--harness]` (the flag is read by `mutations.cli_mutate`)
- `revalidate ARTIFACT_ID --manifest MANIFEST [--witness PATH]` (read by `dependencies.cli_revalidate`)
- `what-if ARTIFACT_ID --manifest MANIFEST`, with `LAZY_COMMANDS["what-if"] = "science_gate.dependencies:cli_what_if"`

With `--require-signature`, the run directory is written as usual. Unless the
auth status is SIGNED_VERIFIED, the command prints
`ERROR (PROTOCOL_BROKEN) <run_id>: --require-signature: the receipt is <AUTH_STATUS> (<detail>); the run's own status <STATUS> is recorded in run.json`
first, then the paths, and exits 3. That is the distinct exit within the
0–3 scheme (D3). `reports.ExportValidationError` exits 3 as
`ERROR verify: export validation failed: <first problem>`, and a non-empty
existing `--output` exits 3 as `OUTPUT_EXISTS`.

### 17.10 Reporters that can fail, atomic run directories, one name per quantity (#12, D7, G4, G5; reports)

`_validators.py` (new): `class ExportValidationError(ValueError)` with
`problems: tuple[str, ...]`; `validate_run_json(run) -> tuple[str, ...]`;
`validate_sarif(sarif, run) -> tuple[str, ...]`;
`validate_report_md(text, run) -> tuple[str, ...]`; and `VALIDATORS`, mapping
each file name to its validator. `run` is the `run.json` document. Rules and
problem codes:

- `RUN_CHECKS_EXECUTED_MISMATCH`: `checks_executed` differs from the number of required results that are CHECKED with a non-null `invocation_id`.
- `SARIF_LEVEL_WITHOUT_FAIL`: a result whose `level` is not `"none"` while its kind is not `fail`.
- `SARIF_EXECUTION_SUCCESS_ON_ERROR` and `SARIF_ERROR_WITHOUT_NOTIFICATION`: an ERROR run with `executionSuccessful` true, or without a toolExecutionNotification (D7).
- `SARIF_KIND_MISMATCH`: a result kind that differs from `sarif_classification` of its `run.json` check.
- `SARIF_CHECK_MISSING` and `SARIF_CHECK_UNEXPECTED`: every check id in `declared.checks` appears exactly once, and nothing else appears.
- `REPORT_HEADING_MISSING` and `REPORT_HEADING_ORDER`: the nine `REPORT_HEADINGS` are the first nine `## ` headings, in order.

`write_run` builds and validates every payload before writing anything, and
raises `ExportValidationError` on any problem. `report RUN_DIR` re-runs
`validate_run_json` and `validate_sarif` on the stored files and
`validate_report_md` on the re-rendered text; any problem fails
re-verification (ERROR, exit 3). Fixtures in `fixtures/exporters/` are the
brief's six negative cases, each with the `run.json` it is judged against.
A meta-test swaps each validator for accept-all and shows its fixture test
then fails.

G4, atomic finalization: `write_run` refuses an existing non-empty output
directory (`OUTPUT_EXISTS`); an existing empty one is removed and replaced.
It writes every file with `safe_write` into the staging sibling
`<parent>/.<name>.incomplete` (an older leftover is removed first), then
`os.replace`s the staging directory onto the output path. Both paths are
confined with `_safeio.resolve_under_root`. On any failure the staging
directory is removed (best effort), the error propagates, and the output path
never appears. `report RUN_DIR` rewrites `report.md` and `report.html` each
through `<name>.incomplete` plus `os.replace`. A directory without `run.json`,
or whose name ends `.incomplete`, is `RUN_INCOMPLETE`: ERROR, exit 3, and its
verdict is never rendered. The test simulates ENOSPC on the Nth `safe_write`
and asserts that no output directory and no `report.md` exist afterwards.

G5, one name per quantity: report.md prints the run figure only as
`rows_examined: N (distinct data rows of declared inputs read by an executed check)`.
The per-check sum is never computed or printed, and a check's own figure
appears only on that check's line. Also in report.md: `receipt.auth.json`
joins `RUN_FILES` and FILES; WHAT ACTUALLY RAN lists the PLAN, the controls
and each witness state; WHAT THIS RESULT DOES NOT PROVE gains a line saying
that subprocess and C-extension I/O are invisible to the write-detection
hook (D10).

### 17.11 Numeric forensics (#3, #7, #17, D5; numeric)

`numeric.py` (new) works only in `Decimal` and `Fraction` and takes printed
strings, never floats (FLOAT_FIRST is modelled transiently, as
`Decimal(repr(round(float(text), d)))`, and no float is stored):

- `round_with(value: Decimal, decimals: int, convention: RoundingConvention) -> Decimal`
- `preimage(printed: str, *, conventions: Iterable[RoundingConvention] = (RoundingConvention.HALF_EVEN,)) -> RoundingInterval`, where `RoundingInterval(low, high, low_inclusive, high_inclusive, conventions)` has `contains()` and `to_dict()`
- `grim(mean: str, n: int, *, items: int = 1, conventions=EITHER_HALF) -> NumericTest`
- `grimmer(mean: str, sd: str, n: int, *, items: int = 1, conventions=EITHER_HALF) -> NumericTest`
- `debit(proportion: str, sd: str, n: int, *, conventions=EITHER_HALF) -> NumericTest`
- `metric_feasibility(metrics: Mapping[str, str], *, p: int, n: int, conventions=EITHER_HALF) -> NumericTest`
- `derived_interval(formula: str, operands: Mapping[str, str], *, conventions=EITHER_HALF) -> RoundingInterval`
- `compare_with_tolerance(expected: str, observed: str, *, relative: str = "0", absolute: str = "0") -> NumericTest`
- `rounding_fingerprint(stored: str, printed: str) -> frozenset[RoundingConvention]`

`NumericTest(test, outcome: NumericOutcome, discrimination: Ratio, evidence)`
exposes `holds` (True, False, or None for NOT_TESTABLE), `execution_state`,
`verdict`, `reason` and `failure_modes` (from `NUMERIC_OUTCOME_VERDICTS`), and
`to_dict()`. Discrimination is the fraction of a stated finite grid of
admissible values that the test would reject. For `grim` the grid is every
value with the printed decimals in [⌊x⌋, ⌊x⌋ + 1). Zero discrimination is
NOT_TESTABLE; a test that holds but could not have failed (for example a
tolerance band wider than |expected|) is VACUOUSLY_CONSISTENT. The brief's
acceptance values bind: `grim("5.19", 28)` is INCONSISTENT with nearest
consistent values `"5.18"` and `"5.21"`; `grim("5.18", 28)` is CONSISTENT with
discrimination `"0.72"`; `grim("5.19", 150)` is NOT_TESTABLE with
discrimination `"0"`; `metric_feasibility` gives `n_valid_tptn_pairs == 0`.

`claims.py` registry additions (the claims schema changes through a request):

- claim keys `rounding` (`"HALF_EVEN"` by default, or `"EITHER_HALF"`), `must_derive_from` (`"stored_output"` or null) and `consistency` (`{"test": "grim"|"grimmer"|"debit", "n": int, "items"?: int, "sd"?: str}`)
- derivation keys `formula` (`"difference"|"ratio"|"percent"|"f1"`) and `operands` (an ordered list of claim ids)

Narrated numbers (#7): for a derived claim, A = round(f(printed operands))
and B = round(f(stored full-precision operands)), each at the claim's printed
decimals under its rounding. When the claim equals A but not B, the failure
mode is NARRATED_VERIFICATION: FAIL / SOURCE_MISMATCH with
`must_derive_from: stored_output`, otherwise ABSTAIN / REQUIRES_HUMAN_REVIEW.
A == B counts as indistinguishable and is never flagged. Fingerprint: when
the declared convention cannot reproduce the printed digits from the stored
value but another convention can, the result is FAIL / SOURCE_MISMATCH with
PROTOCOL_DRIFT and the fingerprint in evidence. Stored `"0.125"`, claim
`"0.13"`, HALF_EVEN gives the fingerprint {HALF_UP, CEILING}.

Coverage funnel (#17), `claim_registry` evidence `numeric_coverage`:
`{found, declared, parsed, typed, checkable, checked, buckets: {NAME: [{line, text}]}, floor, ratio}`.
`found` is every numeric token the scan finds. `declared` are tokens covered
by a valid `not_claims` declaration. `parsed` have a candidate reading, and
`typed` exactly one. `checkable` match a registered claim value, and
`checked` were compared against a stored output. The ratio is
`Ratio(checked, found − declared)`. The buckets are at least
DECLARED_NOT_CLAIM, AMBIGUOUS_SEPARATOR, DECIMAL_COMMA_LOCALE,
GARBLED_COMPARATOR, CORRECTED_VALUE, UNREGISTERED and NOT_COMPARED. The floor
is check param `coverage_floor` (a decimal string in [0, 1], default `"1"`).
Below it the check cannot PASS: ABSTAIN / INSUFFICIENT_EVIDENCE with
OMITTED_POPULATION. Consistency tests add `discrimination` and
`discrimination_ratio` as in 17.8. Third-party claims honour D5. Coverage,
narration and consistency findings are recorded after the 0.1.0 disposition
findings, so a claims check that 0.1.0 already decided keeps its primary
reason (requirements 10–12).

### 17.12 Mutation bookkeeping, activation and harness self-mutation (#4, #11, #13, D12; mutations)

`OPERATOR_IDS` = the twenty 0.1.0 operators plus `M21_removed_plan` (21).
`M00_forced_detection` is a harness control, not an operator. It is never in
`OPERATOR_IDS`, never counted and never selectable. It always runs first
after a valid baseline: it flips one hex digit of the sealed head, replays
through `decide()`, and requires `invariant:ledger_chain_intact` to fire.
`M21_removed_plan` removes the PLAN entry, calls `ledger.reseal`, remaps the
results' invocation ids, replays with the new seal, and expects
`invariant:plan_closure` (FAIL). M15's detector becomes
`contract:checks_executed` with status FAIL and signal PARTIAL_EXECUTION
(D1).

`apply_target(target: Target, root: Path) -> AppliedMutant` is the single
application point for every operator, M00 included; it returns the file
digests or the tampered entries and seal. Test doubles replace it. The report
schema becomes `science-gate-mutation-report/v2` and adds:
`forced_detection` (`{mutation_id, target, detected, detector, fired}`);
`counts_as_detected` (the models table, which is hashed into `report_id`);
`buckets` (`{MutationStatus: [sorted ids]}` for every member);
`conservation` (`{generated, executed, generated_holds, executed_holds, disjoint, holds}`);
and `sampled: false` and `reused: false`. Each record adds `status`,
`activation`, `pie_stage`, `mutant_sha256`, `mutant_canonical_sha256` and
`duplicate_of`. The count keys are the six 0.1.0 `COUNT_KEYS` (with
`escaped_mutations` = executed − detected), `generated_mutations`, and
`blind_spot_mutations`, `verifier_error_mutations`,
`timed_out_mutations`, `flaky_mutations`, `not_activated_mutations`,
`noop_mutations`, `canonically_equivalent_mutations`,
`duplicate_mutations` and `suppressed_mutations`.

Conservation, over the sorted id lists: generated = executed ⊎ NOT_APPLICABLE
⊎ SUPPRESSED ⊎ NOOP_MUTATION ⊎ CANONICALLY_EQUIVALENT ⊎ DUPLICATE_MUTANT ⊎
SKIPPED ⊎ NOT_ACTIVATED, and executed (`EXECUTED_MUTATION_STATUSES`) =
DETECTED ⊎ BLIND_SPOT ⊎ VERIFIER_ERROR ⊎ TIMED_OUT ⊎ FLAKY.

Digests: a tree digest is `sha256_canonical` of the sorted
`[relpath, sha256]` pairs. The canonical variant replaces each JSON file
whose digest the manifest does not declare with `sha256_canonical(parsed)`.
For replay operators the digest covers the canonical `(entries, seal)`. A raw
digest equal to the baseline's gives NOOP_MUTATION, which also emits a
harness-defect diagnostic. A canonical digest equal to the baseline's, with a
different raw digest, gives CANONICALLY_EQUIVALENT. A raw digest equal to an
earlier operator's gives DUPLICATE_MUTANT with `duplicate_of`.

Activation (#11): each file-operator verify runs inside
`_audit.recording(under=[mutant root], record_values=True)`. A mutant whose
verify opened no file under its root is NOT_ACTIVATED. DETECTED needs the 0.1.0
detection rule plus each mutated path read from the mutant copy (a deleted
path counts when the run recorded it as MISSING). An expected detection
without that is NOT_ACTIVATED. A verify that raises is VERIFIER_ERROR. Other
executed mutants are BLIND_SPOT with a `pie_stage`:

- NOT_READ: no mutated path was read.
- READ_NOT_INFECTED: the admitted-row and parsed-document digests equal the baseline's.
- INFECTED_NOT_PROPAGATED: no `ValueRead` touched a changed cell, and no consuming check's evidence differs.
- PROPAGATED_NOT_CHECKED: otherwise.

Replay operators (M00, M16, M17, M21) record `activation.mode = "replay"`
and count as activated.

Report status, first match wins:

1. FAIL / INVALID_BASELINE, as in 0.1.0.
2. FAIL / HARNESS_BLIND when M00 was not detected: no counts, no sensitivity, `HARNESS_BLIND_MESSAGE`, exit 1.
3. FAIL / UNMEASURED_MUTANTS when conservation fails: counts shown, no sensitivity.
4. ABSTAIN / INSUFFICIENT_EVIDENCE, with no sensitivity and `NOT_ACTIVATED_MESSAGE`, when file operators were applicable and none was activated.
5. ABSTAIN / INSUFFICIENT_EVIDENCE when nothing executed.
6. FAIL / BLIND_SPOT when any BLIND_SPOT exists.
7. FAIL / PROTOCOL_BROKEN when any VERIFIER_ERROR, TIMED_OUT or FLAKY exists.
8. PASS / VERIFIED.

Sensitivity (detected/executed, 0.1.0 format) appears only in cases 6–8.

`check_mutation_accounting(ctx, spec)` (kind `mutation_accounting`) takes
exactly one declared JSON input holding a mutation report. It recomputes
both identities from `buckets` and the records. Imbalance or overlap gives
FAIL / UNMEASURED_MUTANTS. A report without `buckets` is SKIPPED, labelled
EVIDENCE_MALFORMED. Its `rows_examined` is the number of records.

Harness self-mutation (#13): `HARNESS_MUTANT_IDS` = `H01_apply_noop`,
`H02_status_only_detection`, `H03_crash_credited`, `H04_unexecuted_counted`,
`H05_baseline_unchecked`, `H06_replay_reseals`, `H07_reads_original_tree`.
`mutate_harness(manifest_path, *, registry=REGISTRY) -> HarnessReport` runs
the honest harness and each variant over the given PASS-baseline tree. For H05
it also uses a copy whose first required input was emptied. A variant is
killed when its status, reason, any record's status or any count differs from
the honest run in the same call. The report has schema
`science-gate-harness-report/v1`, id `har-<16 hex>`, records
`{harness_mutant_id, description, killed, differences}` and
`harness_sensitivity` (a `Ratio(killed, 7)`). It is PASS only at 7/7,
otherwise FAIL / HARNESS_BLIND. `mutate MANIFEST --harness` prints and
writes it.

### 17.13 Witnessed revalidation, verifier drift and what-if (#5, #22, D6; dependencies)

Recompute witness: a document `science-gate-recompute-witness/v1` with keys
`{schema, node_id, invocation_id, started_at, completed_at, inputs: {parent_node_id: sha256}, output_sha256}`.
`RecomputeWitness` mirrors it, with
`witness_id = "wit-" + sha256_canonical(document)[:16]`.
`load_witness(root: Path, relpath: str) -> RecomputeWitness`.
`DependencyGraph.revalidate(artifact_id, observe=None, *, at=None, witness: RecomputeWitness | None = None) -> Revalidation`.
For a node with at least one parent whose file digest is unchanged:
REVALIDATED_UNCHANGED requires a witness for that node that started strictly
after the `at` of the transition that last made the node
STALE_PENDING_REVALIDATION, with `started_at` ≤ `completed_at`, with
`inputs[p]` equal to each stale-causing parent p's current `recorded_sha256`,
and with `output_sha256` equal to the node's recorded digest and its current
file digest. Without a witness the outcome is `REFUSED_VACUOUS_CUTOFF`; with
an invalid one it is `REFUSED_INVALID_WITNESS` (both new
`RevalidationOutcome` members). The node stays STALE_PENDING_REVALIDATION,
and history appends
`{from: STALE_PENDING_REVALIDATION, to: STALE_PENDING_REVALIDATION, reason: "VACUOUS_CUTOFF" | "INVALID_WITNESS", witness_id}`.
A changed digest and every root node keep the 0.1.0 rules. History entries
gain `witness_id` and `cause_category` (a `StaleCause` value).

Verifier drift: graph nodes may declare
`backed_by_checks: [{"check_id", "kind", "version", "params_sha256", "tool_version"}]`.
`dependency_currency` compares each entry with the current manifest (17.4
formula, and `__version__`). A difference, or a check that no longer exists,
makes that node and its descendants STALE_PENDING_REVALIDATION in memory, with
the cause `verifier:<check_id>` (category VERIFIER; ids never contain `:`),
reported as `verifier_drift: {node_id: [check_ids]}`. Nothing is written
during `verify`. `dependency_currency` adds the failure mode VACUOUS_CUTOFF
when a pending publication node has a refused cutoff in its history since it
last went stale.

What-if (#22): `what_if(manifest_path, artifact_id) -> WhatIfReport` and
`cli_what_if(args) -> int`. In memory, it gives the artifact a synthetic
digest change and runs the impact walk on a copy of the state. It is PASS
when every declared descendant became STALE_PENDING_REVALIDATION and the
currency assessment would FAIL, if any publication node descends. It is
FAIL / BLIND_SPOT when a descendant was not marked, or when the assessment
would not FAIL. With no descendants it is NOT_APPLICABLE, ABSTAIN /
INSUFFICIENT_EVIDENCE. Schema `science-gate-what-if/v1`, id
`wif-<16 hex>`. It writes nothing and prints the headline, a blank line and
the Markdown report.

### 17.14 Resolver negative controls and editorial status (#8, #10; citations)

Frozen record keys added: `canary` (bool, default false),
`handle_response_code` (int or null) and `registered_at` (ISO UTC or null).

- **Canaries.** A canary DOI is `<prefix>/science-gate-canary-<12 lowercase hex>`, where the prefix is the text before the first `/`. In frozen mode, every prefix the run touches needs a frozen canary record (`canary: true`, outcome NOT_FOUND, `handle_response_code` 100, the six provenance fields). A touched prefix without one is ABSTAIN / BLIND_SPOT. In live mode the nonce is `sha256(run_id)[:12]`, using the new `CheckContext.run_id` (engine). A live canary is asked for a prefix only after a live lookup there produced an answer that would be DOI_RESOLVED, because a canary vouches for positives. It is asked of the Handle API (`adapters/doi_handle.py`; the body code must be 100) and only then of the same content-negotiation resolver, which must answer HTTP 404 or 410 (a returned work is a resolution). The frozen requirement applies to every prefix under which the capture answered at least one cited DOI; a prefix answered only live needs the live canary instead. Requirement 17's single live call stands.
- **A canary that resolves.** If any canary maps to DOI_RESOLVED, the check is FAIL / BLIND_SPOT with VACUOUS_PASS, and every DOI under that prefix is reported SOURCE_UNAVAILABLE, never DOI_RESOLVED. A canary mapping to DOI_RESOLVED or DOI_TARGET_MISMATCH resolves. Evidence: `canaries` (frozen controls) and `live_canaries` (live controls), each `{prefix: {doi, state, handle_response_code, holds, source, detail, provenance}}`, and `distrusted_prefixes`. Works under a distrusted prefix leave the metadata reference pool, so a fabricated record cannot cause a false CONFLATED_ENTRY.
- **Body codes decide.** When `handle_response_code` is present it decides alone: 1 is DOI_RESOLVED, 100 or 200 is DOI_NOT_RESOLVED_AT_CAPTURE, anything else is SOURCE_UNAVAILABLE. When absent, `outcome` decides as in 0.1.0. `http_status` never decides. A cited record with body code 1 but no captured work is SOURCE_UNAVAILABLE (NO_REFERENCE_WORK). `adapters/doi_handle.py` (new) performs live Handle lookups through `NetworkPolicy.opener` only.
- **Impossible timelines.** A log invocation whose `retrieved_at` precedes the record's `registered_at` makes that entry ABSTAIN / UNVERIFIED with NARRATED_VERIFICATION, and both timestamps go into evidence. A frozen record captured before `registered_at` is SOURCE_UNAVAILABLE ("snapshot predates registration"), never "not found".

Editorial status (#10): kind `editorial_status`
(`science_gate.citations:check_editorial_status`). Its input is exactly one
declared JSON input, an array of channel snapshots
`{source, snapshot_sha256, captured_at, consulted_dois: [...], notices: [{doi, type, date, notice_id}]}`,
with `type` a `NoticeType` value. Optional params:
`{"defect_windows": [{"source", "start", "end"}]}`. Cited DOIs come from
`citations.entries`. Per cited DOI:

- Its channels are the snapshots whose `source` is an `EditorialChannel` value and that consulted it, minus those captured inside a defect window for their source; those are listed as downgraded. Any other source (an aggregator's retraction flag, for example) is listed under `ignored_sources` and never counted.
- Notices are ordered by date, and the latest RETRACTION or REINSTATEMENT decides between RETRACTED and REINSTATED. Failing that, the status is CORRECTED or EXPRESSION_OF_CONCERN if such a notice exists; then NOT_RETRACTED_WITHIN_SCOPE with at least two channels; otherwise UNDETERMINED.

The check is FAIL / SOURCE_MISMATCH when any DOI is RETRACTED; ABSTAIN /
REQUIRES_HUMAN_REVIEW on EXPRESSION_OF_CONCERN; ABSTAIN /
INSUFFICIENT_EVIDENCE when a DOI has a single channel; ABSTAIN /
SOURCE_UNAVAILABLE when it has none; and PASS otherwise. Evidence holds, per
DOI, `{status, channels: [{source, snapshot_sha256}], notices, downgraded}`,
and document-level counts per status. Acceptance case (e) uses the existing
graph: the editorial snapshot file is a SOURCE_SNAPSHOT node with edges to
the dependent nodes, so advancing its digest makes them stale through the
0.1.0 impact walk, with no dependencies change. Fixtures are synthetic only;
no Retraction Watch rows are shipped.

### 17.15 Claim-to-invocation join (#6; assertions)

`assertions.py` (new) provides kind `claim_join`:
`check_claim_join(ctx, spec)`, `preload_claim_join(ctx)` and
`falsify_claim_join(ctx, spec, result)`. Its input is exactly one declared
JSON input whose records are assertions:
`{claim_id, kind: AssertionKind, cites: "<invocation_id>", claimed_at: ISO UTC, artifact_sha256: hex|null, claimed_result: Status value}`.
Unknown keys are refused, and a malformed record makes the check SKIPPED,
labelled EVIDENCE_MALFORMED. The required param `sealed_run` (section 2
refuses a key named `run` at any depth) is the
manifest-relative directory of a sealed run; its `ledger.jsonl` (bytes) and
`run.json` (from which only `run_id`, `ledger_head_sha256` and
`ledger_length` are read) are read through `ctx.read_document` under the
roles `claim_join.ledger` and `claim_join.run`, and preloaded.

`join_claims(assertions, entries, seal) -> ClaimJoin` is pure.

1. The chain is `verify_chain(entries, head, length, run_id=...)`. A broken chain makes every assertion NARRATED and none BACKED.
2. Otherwise each assertion is judged in order: no terminal invocation with that id is NARRATED (`CITED_INVOCATION_ABSENT`); `completed_at` after `claimed_at` is NARRATED (`IMPOSSIBLE_TIMELINE`, with both timestamps); `artifact_sha256` null or not among the invocation's `input_sha256s` values is NARRATED (`ARTIFACT_UNBOUND` or `ARTIFACT_MISMATCH`); a verdict that differs from `claimed_result` is CONTRADICTED; anything else is BACKED.
3. ORPHANED lists the terminal FAIL and ERROR invocations that no assertion cites, excluding controls (check ids starting `control:`).

The check is FAIL / SOURCE_MISMATCH on any CONTRADICTED; otherwise ABSTAIN /
UNVERIFIED with NARRATED_VERIFICATION on any NARRATED; otherwise PASS.
ORPHANED is listed only and does not decide. `rows_examined` is the number of
assertions. Evidence: `chain` (`ChainVerification.to_dict()`), `assertions`
(`[{claim_id, kind, cites, outcome, detail}]`), `buckets` (`{outcome: [ids]}`)
and `counts` (`{outcome: n}`). An OpenTelemetry span importer is not built in
this stage.

### 17.16 New check kinds and registry wiring (engine)

| kind | `REGISTRY` target | `PRELOADS` | input | owner |
|---|---|---|---|---|
| `claim_join` | `science_gate.assertions:check_claim_join` | `science_gate.assertions:preload_claim_join` | one JSON (or JSONL) input of assertions; param `sealed_run` | assertions |
| `editorial_status` | `science_gate.citations:check_editorial_status` | none | one JSON input of channel snapshots | citations |
| `mutation_accounting` | `science_gate.mutations:check_mutation_accounting` | none | one JSON input holding a mutation report | mutations |

In one change, the engine adds these entries to `REGISTRY`, `PRELOADS` and
`FALSIFIERS` (17.5), and the three kinds to `BUILTIN_CHECK_KINDS`.
`schemas/manifest.schema.json` gains them through a request; until it lands,
the kind-enum test in `tests/test_manifests.py` is red, and the engine lists
that under known gaps.
`CheckContext` gains `run_id: str | None` (set before any check runs) and
`overlay(case)`. `verify()` gains
`falsifiers: Mapping[str, str] = FALSIFIERS` beside `registry`.
`VerificationRun` gains `plan`, and `controls` mirrors `RunResult.controls`.

### 17.17 Acceptance test files and fixtures

| test file | proves | owner |
|---|---|---|
| `tests/test_falsifiers.py` | #1 (a)–(d), on `fixtures/core/valid` (the engine's "demo"); the canary | engine |
| `tests/test_plan.py` | #2 (a)–(d), with seq 1 for the brief's "entry 0"; `reseal` | engine |
| `tests/test_harness_pin.py` | #9 (a)–(d); `_audit` nesting and gating | engine |
| `tests/test_verdict_lattice.py` | #23, #24, D1, D2, G1–G3 (failing first), the precedence of 17.7 | engine |
| `tests/test_receipt_auth.py` | #15, D9: unsigned with `--require-signature` exits 3; a corrupted HMAC is SIGNED_FAILED; no written file has an empty signature | integrity |
| `tests/test_canonical_vectors.py` | #16, D8 vectors | integrity |
| `tests/test_exporter_validators.py` | #12 (six negative fixtures, the meta-test, a tampered `results.sarif` giving exit 3), D7 | reports |
| `tests/test_reports.py` | G4 (simulated ENOSPC), G5 (failing first) | reports |
| `tests/test_numeric_forensics.py` | #3 (a)–(f), including the property test | numeric |
| `tests/test_narrated_numbers.py` | #7 (a)–(d), D5 | numeric |
| `tests/test_numeric_coverage.py` | #17 | numeric |
| `tests/test_mutation_accounting.py` | #4 (a)–(f), D12, M21 | mutations |
| `tests/test_activation.py` | #11 (a)–(d) | mutations |
| `tests/test_harness_mutation.py` | #13: `harness_sensitivity` 7/7, each variant killed | mutations |
| `tests/test_witnessed_revalidation.py` | #5 (a)–(e), D6 | dependencies |
| `tests/test_staleness_whatif.py` | #22 | dependencies |
| `tests/test_resolver_controls.py` | #8 (a)–(d), using injected openers only | citations |
| `tests/test_editorial_status.py` | #10 (a)–(e) | citations |
| `tests/test_claim_join.py` | #6: the five-assertion case (four assertion records plus one uncited FAIL invocation, since ORPHANED classifies invocations) gives FAIL with {BACKED: 1, NARRATED: 2, CONTRADICTED: 1, ORPHANED: ≥1}; a tampered chain gives every assertion NARRATED | assertions |

Fixtures each builder owns and must keep consistent:

- `fixtures/core/**` (engine): add `core/header-only`, a header-only CSV plus a pinned summary, expected ABSTAIN / INSUFFICIENT_EVIDENCE with `rows_examined` 0, VACUOUS_PASS present and PARTIAL_EXECUTION absent. `core/valid` stays PASS with every check WITNESSED.
- `fixtures/exporters/**` (reports): the six negative fixtures and their `run.json`.
- `fixtures/numeric/**` and `fixtures/claims/**` (numeric): the forensic cases. Existing claims trees keep their 0.1.0 outcomes.
- `fixtures/mutations/**` (mutations): `rich/citations/frozen.json` gains a canary record for each touched prefix, so `rich/manifest.json` stays PASS (requirement 13 and the demo). Add an activation tree with a file that no check opens.
- `fixtures/dependencies/**` (dependencies): witness documents and a `backed_by_checks` graph.
- `fixtures/citations/**` (citations): every tree that expects a resolver PASS gains canary records; add the resolver-control and editorial trees.
- `fixtures/assertions/**` (assertions): a synthetic sealed run (`ledger.jsonl` and `run.json`, built with `ledger.Ledger`, not by `verify`) and the five-assertion case.

All fixtures are synthetic: invented names, DOIs under `10.5555`, and
generated data.

### 17.18 Integration re-baseline (unowned files)

The orchestrator applies these at integration. Each builder repeats, in
`requests_for_shared_files`, the ones its change causes.

- `tests/test_required.py`: r22 expects one PLAN entry plus two entries per invocation, and invocations = results + controls; the requirement itself is unchanged. r27 expects `len(OPERATOR_IDS) - 1 - len(CORE_NOT_APPLICABLE)` skipped operators.
- `packaging.py` and `tests/test_packaging.py`: `expected/receipt.json` becomes a bare statement with `expected/receipt.auth.json` beside it, written by `receipts.write_receipt`; the predicate is read at the statement's top level.
- `schemas/*.json`: the key sets of 17.11 (claims), 17.13 (graph and its transitions), 17.14 (frozen records) and the kind enum (manifest).
- `tests/test_examples.py`, `tests/test_html.py`, `tests/test_demo.py` and `demo.py`: `rows_examined` (G1), ledger lengths and the mutation report schema shift. The expected numbers are re-baselined; nothing is loosened.

All four were applied at integration. Re-baselined expectations, each
because section 17 changed the behaviour it pins, with nothing loosened:

- `tests/test_required.py` r22 (controls are invocations; the PLAN is one
  more entry) and r27 (21 operators). Every other requirement test is
  unchanged.
- `tests/test_examples.py`: the field survey examines 6 rows, not 10 (G1),
  and its emptied input is a justified shortfall: the six readers are
  NOT_APPLICABLE labelled EMPTY_POPULATION, so the run's reasons name
  INSUFFICIENT_EVIDENCE and not PARTIAL_EXECUTION, and the FAIL still comes
  from the broken declared closure (G2). `examples/README.md` says the same.
- `tests/test_html.py`: 16 contract invariants instead of 10, controls
  excluded from the placed ledger starts, 21 operators.
- `tests/test_packaging.py`: the statement and its sidecar.
- `tests/test_demo.py`: 31 expectations (17.19).

No fixture's expected outcome changed at integration; the builders'
fixture re-baselines are recorded in 17.19.

### 17.19 Recorded build and integration decisions

Where a builder had to decide something this section left open, or found
that a rule could not be built as written, the decision is recorded here and
binds like the rest of section 17. In-place amendments above: the falsifier
record's `control_id` (17.5), `plan_closure` over planned controls (17.4),
`hook_errors` and the PLAN comparison in `harness_pins_intact` (17.6), the
canary rules (17.14), and the `sealed_run` param (17.15, 17.16).

Engine (17.4–17.8, 17.16):

- An overlay or canary context answers only from memory: a file the base
  context never read is OPEN_FAILED with diagnostic `OVERLAY_UNREAD`, and
  every control context is offline, so no negative control makes a request.
- A generator that raises, or returns anything but distinct `FalsifierCase`s
  over declared inputs, leaves the subject UNWITNESSED (ABSTAIN /
  BLIND_SPOT). A case that changes nothing the checker reads is ACCEPTED, so
  a careless generator can fail an honest checker but never pass one.
- An empty aggregate (lattice NONE) also records VACUOUS_PASS.
  `controls.plan.pins` is the number of pins; the list is in the PLAN body.
  `RunResult.controls` defaults to all-null controls with an empty
  transition list.
- The audit hook keeps its recorders in a `ContextVar`, so a write made from
  another thread is seen only through the post-run re-hash. Event paths are
  absolute and `normcase`d. A recorder with neither `watch` nor `under`
  records every event; value reads are attributed only while
  `current_check` names a check.
- Public helpers beyond the names above: `verifier.memory_input`,
  `module_source_sha256`, `params_sha256`, `checker_sha256`,
  `CheckContext.bind_run_id`; `invariants.CONTROL_PREFIX`,
  `FALSIFIER_PREFIX`, `COMPARATOR_CONTROL`, `CANARY_MUST_FAIL`,
  `CANARY_MUST_PASS`, `PLANNED_CONTROLS`, `COMPARATOR_PAIRS`,
  `falsifier_check_id`, `is_control`, `run_comparator_self_test`.

Integrity (17.9):

- The in-memory receipt record is `{body, content_sha256, signature_state,
  signature, key_id, detail}` (`receipts.RECORD_KEYS`); `detail` feeds the
  unsigned sidecar. `seal_body(body, resolution)` takes the key resolution.
- Verification of two documents is
  `verify_receipt_documents(statement, auth, *, statement_name, key,
  require_signature)`; `ReceiptVerification` also carries `run_id`, and
  `signature_verified` derives from `auth_status`.
- `report --require-signature` ends its headline with "the report's own
  status <STATUS> is recorded in report.md". A missing or malformed sidecar
  has no AuthStatus; the headline then says "the receipt's authentication
  could not be determined (<first problem>)". `verify --require-signature`
  judges the files as written on disk.
- `strict_loads` in data mode carries an integer beyond ±(2^53 − 1) as a
  Decimal (so it is hashed as a decimal string, never as a JSON number);
  `integers_only=True` refuses it with kind `INTEGER_OUT_OF_RANGE`.

Reports (17.10):

- Extra problem codes: `RUN_JSON_MALFORMED`, `SARIF_MALFORMED` and
  `REPORT_MALFORMED` (a tampered export is a problem, never a crash);
  `REPORT_ROWS_EXAMINED_MISMATCH` (exactly one line
  `- rows_examined: N (distinct data rows of declared inputs read by an
  executed check)`, with N equal to `run.json`'s figure, or `unknown` for
  null); and `reports.SARIF_NOT_DERIVED` (`report RUN_DIR` requires
  `results.sarif` to equal the log `run.json` derives, because neither the
  receipt nor the evidence manifest attests it).
- `SARIF_ERROR_WITHOUT_NOTIFICATION` needs an error-level notification.
  Every `VALIDATORS` entry takes `(export, run)`; `validate_exports` and
  `rows_examined_line` are helpers.
- An output or staging path that is a link is refused (`SYMLINK_TARGET`);
  the directory rename retries a transient `PermissionError`; a file at the
  output path is also `OUTPUT_EXISTS`. A re-rendered `report.md` is
  validated; a problem fails re-verification, and an ERROR report that would
  still be invalid raises `ExportValidationError` and writes nothing.
- G5 also binds the HTML view: its run figure is `rows_examined` with the
  same meaning, and its check table column is "Subject records examined".

Numeric (17.11):

- The coverage funnel adds the buckets `NOT_A_NUMBER` (no reading under any
  convention) and `UNDECLARED_SEPARATOR` (a single reading only through an
  undeclared grouping mark). The claims fixtures keep their 0.1.0 status,
  reason and exit code; their `claims_check` failure modes gain the new
  findings recorded after the 0.1.0 ones (`fixtures/claims/expected.json`).
- Narration outcomes beyond the brief: NOT_REPRODUCED (the claim matches
  neither recomputation: FAIL / SOURCE_MISMATCH), OPERANDS_UNAVAILABLE
  (ABSTAIN / INSUFFICIENT_EVIDENCE) and NOT_EVALUATED (ABSTAIN /
  REQUIRES_HUMAN_REVIEW). Under EITHER_HALF, A and B are sets.
- Discrimination grids: GRIMMER and DEBIT use the SD's unit grid at its
  printed decimals; `metric_feasibility` varies one metric at a time;
  `compare_with_tolerance` probes ±10 units of the observed value's last
  digit. `preimage`, `derived_interval`, `grimmer` and `debit` refuse
  FLOAT_FIRST.
- A zero-byte registry or manuscript is EMPTY_POPULATION; a missing one is
  INPUT_UNAVAILABLE.

Mutations (17.12):

- H03 cannot be observed on a tree a correct engine verifies, so
  `mutate_harness` also runs the honest harness and H03 on a crash probe;
  the harness report states it. `mutate` and `mutate_harness` accept
  `falsifiers=`, and `mutate_harness` `exclude=`.
- `mutate --harness` writes the mutation report and `harness-report.json`
  and `.md`, prints both headlines, and exits with the more severe status.
- A copy mutant's digest covers the files and the registry, so a replaced
  checker (M15) is not a NOOP. M21 also renames the invocation ids named
  inside entry evidence before resealing, as a thorough forger would.
- `forced_detection.detector` is `invariant:ledger_chain_intact`. Case 4
  (nothing activated) needs at least one file- or registry-mode mutant to
  have reached DETECTED, BLIND_SPOT or NOT_ACTIVATED, all of them
  NOT_ACTIVATED. NOT_ACTIVATED records keep what their verify produced, with
  `detected` null.
- The HTML view groups the v2 statuses that never executed (NOT_ACTIVATED,
  NOOP_MUTATION, CANONICALLY_EQUIVALENT, DUPLICATE_MUTANT, SUPPRESSED) on
  their own, never as SKIPPED, and notes VERIFIER_ERROR, TIMED_OUT and FLAKY
  as escaped (executed, not detected).

Dependencies (17.13):

- REVALIDATED_CHANGED makes each STALE direct child pending on its own
  account as well, so a later re-hash of the parent cannot launder the real
  upstream change through early cutoff.
- The required parents of a witness are the stale-causing parents, or every
  parent with a recorded digest when the node is pending on its own account.
  "The change" is the last transition into a pending state whose `from`
  differs from its `to` (refusals are not changes). Problem codes:
  WITNESS_FOR_OTHER_NODE, IMPOSSIBLE_TIMELINE, NO_RECORDED_CHANGE,
  WITNESS_PREDATES_CHANGE, MISSING_INPUT, NOT_A_PARENT, UNBOUND_INPUT,
  STALE_INPUT, OUTPUT_MISMATCH.
- A re-hash of a derived node in good standing is also refused (a
  CURRENT→CURRENT VACUOUS_CUTOFF entry). `cause_category` is set on moves
  into STALE and on refusals of a pending node, null elsewhere. The two new
  history keys are optional on read, so a 0.1.0 state file still loads.
- What-if outcome classes are MARKED, ALREADY_PENDING, DECLARED_BY_PERSON
  and NOT_MARKED; nothing marked is ABSTAIN with VACUOUS_PASS. `--witness`
  is relative to the current directory, read confined to its own directory.
  Falsifier case ids: `change-publication-file`, then
  `change-upstream-file`.

Citations (17.14):

- Editorial channels count as distinct sources. A reinstatement supersedes
  a retraction only when dated strictly later. EXPRESSION_OF_CONCERN
  outranks CORRECTED. A notice held only by a downgraded snapshot is not
  counted but gives ABSTAIN / REQUIRES_HUMAN_REVIEW (DOWNGRADED_NOTICE), so a
  declared defect window cannot hide a retraction. `rows_examined` is the
  number of snapshot records.
- The live-answer cache is keyed by the run's manifest, which falsifier
  overlays share, so a run still asks the network at most once per DOI.

Assertions (17.15):

- Input format json or jsonl. Records discovery could not admit are
  malformed assertions (SKIPPED, EVIDENCE_MALFORMED); a PARTIAL input short
  only by deferred records is judged with an ABSTAIN / PARTIAL_EXECUTION
  finding. A broken chain lists no ORPHANED invocations. Detail codes add
  BACKED, CLAIMED_RESULT_CONTRADICTED and LEDGER_CHAIN_BROKEN. Evidence also
  carries `input` and `sealed_run`; a skipped result has no `counts` key
  (unknown, not zero), and `controls.claim_join` sums only results that
  carry it. Falsifier case id `flip-claimed-result`.
- The optional OpenTelemetry `execute_tool` span importer the brief mentions
  is not built (as above); a tool-call id that an assertion cites is
  therefore NARRATED (CITED_INVOCATION_ABSENT).

Integration:

- The demo (18.11) also exercises falsifier witnesses on every PASS and the
  canary pair, the PLAN as the first entry with `plan_closure`, a GRIM
  inconsistency, a narrated number, a resolving resolver canary, the claim
  join buckets, M00 and the conservation identities, M21 caught by
  `plan_closure`, and witnessed revalidation, for 31 expectations. For the
  last, the demo writes two synthetic recompute witnesses timed one second
  before and one second after the change that `impact` recorded, so the
  refusal and the acceptance do not depend on the wall clock.
- Packaging writes `expected/receipt.auth.json` beside the statement; the
  local-execution steps read the predicate at the statement's top level.

## 18. Recorded implementation decisions (0.1.0)

Sections 0 to 16 are the contract, amended by section 17. This section
records how the 0.1.0 code fills the places they leave open, so that readers
and later changes do not have to rediscover them. Where tests enforce a
decision, it binds like the rest of this file. Where section 17 disagrees, 17
wins.

### 18.1 Vocabulary, manifests and input accounting (sections 1 to 3)

- `models.InputState` names an input's state: `PARSED`, `PARTIAL`, `EMPTY`,
  `MISSING`, `REFUSED`, `OPEN_FAILED`, `PARSE_ERROR`, `HASH_MISMATCH`. Only
  `PARSED` is complete. Each input lands in exactly one closure bucket:
  PARSED is admitted, PARTIAL deferred, EMPTY and a required MISSING
  unresolved, an optional MISSING excluded, and REFUSED, OPEN_FAILED,
  PARSE_ERROR and HASH_MISMATCH failed.
- Run-level counters count declared input files; row counts live per input.
  `expected` is INDEPENDENT (it comes from the manifest) and `examined`
  starts UNAVAILABLE until the verifier sets it. The meaningful closure is
  per input: rows accounted against an INDEPENDENT `expected_rows`.
- Some outcomes are unrepresentable: a CheckResult with PASS or FAIL is
  CHECKED, PASS always pairs with VERIFIED, a closure holds only against an
  INDEPENDENT source with known counts, and an absent count is UNAVAILABLE.
- Manifests also accept the `jsonl` input format. Unknown keys are refused
  at every object level (check `params` are free-form but still get the
  unsafe-key refusal). `expected_rows` and a non-UNAVAILABLE
  `denominator_source` are declared together.
- `corpus` may also declare `source_licenses` (a list of
  `{source, license}`) and `approved_redactions` (a list of
  `{target, description}`). Both are recorded as declared and never
  verified; absent means NOT_DECLARED.
- `_safeio` adds the code `SYMLINK_LOOP`.

### 18.2 Ledger and invariants (section 4)

- Each invocation is two append-only entries that share one
  `invocation_id`: a STARTED entry written before the check runs and a
  terminal entry written after. The id derives from the STARTED entry's
  `seq`, so `ledger_length` counts entries, not invocations, and a missing
  terminal entry is provable.
- The four `pass_requires_*` invariants apply only when a check result is
  PASS or the run's tentative status is PASS; otherwise they are not
  applicable (`holds` null). `invariants.VIOLATION_OUTCOMES` maps each
  invariant to its status, reason and failure mode. The detail of
  `pass_requires_examined_rows` is a per-check total ("per-check rows
  examined total=N"); `run.json`'s `rows_examined` counts distinct rows.

### 18.3 Engine and decision (sections 5 and 6)

- `CheckOutcome` has one more field, `claim_tallies`, which feeds
  `checked_claims_le_invocations`.
- `verifier.Findings`, `takes_no_inputs`, `document_unavailable` and
  `malformed_document` are public, so specialist checks fold findings into
  a verdict by the same rule.
- Before any check runs, the engine reads every declared role document and,
  through `verifier.PRELOADS`, every file that a check of a declared kind
  will read: stored claim outputs (`claims.preload_stored_outputs`), and
  dependency node files and the saved graph state
  (`dependencies.preload_graph_files`). Their digests feed the run id,
  every check sees the same bytes, and `summary_consistency` can name them.
- Run-level check counters count required checks only. A required check
  counts as executed only if it reached CHECKED and has a terminal ledger
  invocation. Extra counters: `checks_declared`, `checks_errored`,
  `checks_skipped`, `checks_not_applicable`, `inputs_parsed`,
  `inputs_examined`. Unknown values are null.
- `decide()`: a FAIL or ABSTAIN from an optional check stays visible but
  does not decide the run; an ERROR from any check always does. An input
  REFUSED for a path-safety reason makes the run ERROR. HASH_MISMATCH on any
  input makes the run FAIL. Findings are gathered in the order manifest,
  inputs, checks, contract, invariants, and that order breaks ties for the
  primary reason.
- Role-document formats the verifier defines: `science-gate-snapshot/v1`,
  `science-gate-reviews/v1`, `science-gate-time-sources/v1` (a window plus
  events with `local_time`, `timezone` and `utc`) and
  `science-gate-summary/v1` (`status`, `pinned.inputs`, `pinned.documents`).
  Output schemas: `science-gate-run/v1`, and
  `science-gate-evidence-manifest/v1`, whose `absent` list names missing
  evidence instead of dropping it.
- `time_source` accepts only `UTC`, `Z` or a fixed offset; a named zone is
  ABSTAIN with REQUIRES_HUMAN_REVIEW. `snapshot_completeness` claims a
  deleted row only for a fully PARSED input.
- `summary_consistency`: a PASS summary that pins nothing is ABSTAIN with
  UNVERIFIED. Every evidence file it does not pin is reported as ABSTAIN
  with BLIND_SPOT: declared inputs, declared role documents, and preloaded
  files that exist (stored outputs, node files), except the summary itself
  and files that are declared inputs. A pinned file that changed is FAIL with
  SOURCE_MISMATCH.
- Every command runs inside one `_redact.redaction_scope()`, which reads the
  secret-named environment variables once; `verify()` enters its own scope.

### 18.4 Claims (section 7)

- The registry is `{schema: "science-gate-claims/v1", claims: [...],
  not_claims?}`. `not_claims` lists numbers a reviewer declared are not
  claims, pinned to the manuscript's sha256; after any manuscript edit, none
  of them apply.
- A selector is an RFC 6901 JSON Pointer into a JSON stored output, or
  `{row: {column: cell}, column}`, which selects exactly one CSV row. Stored
  outputs are read with the role `claims.stored_output`.
- Only the stored-output link is tested (DIGEST_MATCHES, DIGEST_MISMATCH,
  UNAVAILABLE, or MISSING). The other links are checked for presence and
  reported as DECLARED, never as confirmed.
- Each claim gets one disposition, in this precedence:
  STORED_OUTPUT_CHANGED and VALUE_DISAGREES (FAIL SOURCE_MISMATCH),
  EPHEMERAL_CLAIM and INCOMPLETE_CHAIN (ABSTAIN UNVERIFIED),
  STORED_OUTPUT_UNAVAILABLE and VALUE_NOT_LOCATED (ABSTAIN
  INSUFFICIENT_EVIDENCE), REQUIRES_HUMAN_REVIEW, RESOLVED. FAIL needs a
  contradicted recorded fact, never absent evidence.
- The manuscript scan (`claims.SCAN_RULE`) skips identifiers and masks URLs
  and DOIs. A token matches a claim only when its value and its printed
  decimals are equal. With a registry but no manuscript, the check is
  ABSTAIN with BLIND_SPOT. `rows_examined` counts claims plus manuscript
  tokens.

### 18.5 Dependencies (section 8)

- Node paths are relative to the manifest directory. The graph's `schema`
  key is optional (`science-gate-graph/v1` when present).
- `graph-state.json` (`science-gate-graph-state/v1`) holds only transitions
  this tool made; `graph.json` is never rewritten. A state file that exists
  but cannot be used is never ignored.
- History entries add `trigger`, `recorded_sha256_before`,
  `recorded_sha256_after` and `observed_sha256` to `{at, from, to, reason}`.
- `impact` also marks the origin itself. Each pending node keeps
  `stale_because`; early cutoff removes one cause and restores a node only
  when none remains, to the state recorded before it went stale.
- `revalidate` has outcomes beyond the contract's two:
  REFUSED_UPSTREAM_PENDING, NO_FILE_TO_HASH and FILE_UNAVAILABLE.
- `publication_block.blocked` is true, false (only when the assessment is
  PASS) or null (undetermined).
- The commands print the headline, the two paths written
  (`graph-state.json`, then `impact-report.json` or
  `revalidation-report.json`, schema `science-gate-impact/v1`), a blank line
  and the Markdown report.

### 18.6 Citations (section 9)

- Documents: `science-gate-citations/v1` (each citation with DOI, title,
  `{family, given}` authors, year, journal, volume and issue),
  `science-gate-citations-frozen/v1` (one record per DOI with outcome FOUND,
  NOT_FOUND or ERROR, the HTTP status, the work and the six provenance
  fields), and an optional `science-gate-verification-log/v1` tag on the
  log.
- The primary disposition is a MetadataState value or SOURCE_UNAVAILABLE.
  RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES is used only for a captured
  NOT_FOUND answer. Defects: DOI_WORK_MISMATCH, TITLE_MISMATCH,
  AUTHOR_MISMATCH, AUTHOR_ORDER_MISMATCH, YEAR_MISMATCH, JOURNAL_MISMATCH,
  VOLUME_MISMATCH, ISSUE_MISMATCH, CONFLATED_ENTRY.
- Live lookups only fill gaps: a usable frozen record always answers, and
  each DOI is fetched live at most once per run. The three citation checks
  take no inputs and no params.

### 18.7 Mutation testing (section 10)

- Detection is judged from the verifier's findings: the expected detector
  must produce a finding with an allowed status and signal. A verifier crash
  under a mutant is an escape. Records add `target`, and the result fields
  of a mutation that did not execute are null.
- The report schema is `science-gate-mutation-report/v1`. The count keys sit
  at top level. Sensitivity is `{detected, executed, fraction, decimal}`,
  rounded ROUND_HALF_EVEN to 4 places.
- Operators that change an input's bytes re-declare its digest; M07 covers
  the digest itself. M13 acts on the citation verification log. M16 and M17
  replay the sealed baseline through `decide`. Every verify runs offline.
- `mutate` writes `mutation-report.json`, `mutation-report.md` and
  `mutation-report.html`. The page is the baseline run's page (built from an
  unsigned receipt that is never written) with the detected-versus-blind-spot
  constellation.

### 18.8 Receipts (section 11)

- Subject names are input ids. The predicate also carries every input's
  state and digest, each check's `evidence_sha256` and the invariant
  outcomes, so an evidence change beneath an unchanged PASS changes
  `content_sha256`.
- Signing uses the key file's exact bytes. An empty, oversized, missing or
  unreadable key file gives UNSIGNED.

### 18.9 Reports (section 12)

- The HTML contract is `science_gate._html.render(run, mutation=None) ->
  str`, where `run` is the `run.json` document. A re-rendered run carries
  `reverification`, and a rejected one is passed as ERROR with
  `recorded_status`. The renderer re-reads a mutation report rather than
  trusting it, and draws a recorded PASS that the document's own figures
  contradict as unsupported.
- `report.md` adds FILES and, on re-render, RE-VERIFICATION after the nine
  contract headings. A `graph-state.json` that does not exist yet is listed
  as "no saved graph state ...: the graph's declared node states were used".
- `report RUN_DIR` also checks `run.json` against the receipt predicate and
  each check against its terminal ledger entry; any mismatch is ERROR.

### 18.10 Packaging (section 13)

- Layout: `package.json` (`science-gate-package/v1`, written last),
  `schemas/`, `expected/receipt.json`, and `evaluation/` holding the
  manifest-relative paths. The expected results are the reproducible
  projection of the receipt predicate (`packaging.REPRODUCIBLE_FIELDS`).
- "An input directory" is the manifest directory. "Default synthetic
  permissions" means a SYNTHETIC corpus that declares no permission keys.
  The manifest follows the data rule. Extra refusals: EVALUATION_NOT_ALLOWED
  and UNSAFE_DECLARED_PATH. Exit 0 for a COMPLETE package, 2 for an
  INCOMPLETE one, 3 for any refusal.
- `source_licenses` and `approved_redactions` are recorded as DECLARED (as
  the manifest states them) or NOT_DECLARED. The tool's own license
  assertion is always NOASSERTION.

### 18.11 Packaged data and the demo (section 14)

- `fixtures/` and `schemas/` ship inside the wheel as the data-only
  subpackages `science_gate._fixtures` and `science_gate._schemas`.
  `science_gate._resources.bundled_dir()` finds them there or, in a source
  checkout, at the repository root.
- `demo` copies the fixtures it needs into `--output` (a new temporary
  directory by default; an existing non-empty directory is refused with exit
  3), runs `verify`, `report`, `mutate`, `impact`, `revalidate` and
  `package` in process, and compares each outcome with an expectation
  written in advance. It prints the headline, the paths written, a blank
  line and the expected-versus-actual table, and writes `demo-summary.json`
  (`science-gate-demo/v1`) and `demo-summary.md`. It exits 0 only when every
  expectation holds, and 1 otherwise.
