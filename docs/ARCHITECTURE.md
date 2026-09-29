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
| `receipt.json` | the run receipt |
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
