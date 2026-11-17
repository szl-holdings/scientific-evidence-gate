# scientific-evidence-gate

A local command-line evidence gate for scientific artifacts. It checks a
declared set of inputs, documents and checks, and reports what was actually
examined, what actually ran, and what could not be established. Its governing
rule:

> A passing check must emit enough evidence to prove that it had the
> opportunity to fail.

It runs on Python 3.11 or later with the standard library only. It needs no
network access unless a manifest or the `--live` flag asks for live citation
lookups, and it never starts a subprocess.

Status: version 0.1.0, unreleased. License: NOASSERTION (no license has been
chosen; see [License status](#license-status)).

## What it is, and what it is not

The tool answers narrow questions about integrity and about a declared
evaluation:

- Were these the exact inputs, documents and tool version claimed (digests,
  row accounting, a hash-chained execution ledger that opens with the run's
  plan)?
- Did every declared check run, reach a terminal result, examine at least one
  data row, and show that it could have failed?
- Do recorded values, citations, claims, reviews, timestamps, agent
  assertions and dependency states agree with each other, under the declared
  rules?

It does not answer whether a conclusion is true. Every output keeps three
kinds of evidence apart:

| Boundary | Meaning | Established here? |
|---|---|---|
| Integrity | Was this the exact artifact, input, execution and version claimed? | Yes, within the declared scope |
| Performance | How did the fixed system behave on the declared evaluation? | Yes, for that one evaluation |
| Scientific validity | Does the conclusion hold in its intended domain? | **Never** |

The receipt states Performance in two labelled parts: `CHECKER:` (how the
checkers themselves behaved: falsifier witnesses, the canary pair, the
comparator self-test) and `RUN:` (the tally of the run's checks). Every run
receipt carries this sentence, verbatim:

> A receipt supports integrity, provenance, and replayability. It does not establish scientific truth, accuracy, safety, or fitness for use.

## What a PASS has to carry

A run is PASS only when all of the following hold. Each item is a named
invariant or contract field in `run.json`, so a missing item is visible
rather than assumed.

- **A plan, committed first.** The ledger's first entry is the run's PLAN:
  the inputs, checks, parameter and checker digests, and pinned files it
  intends to use, hash-chained before any check starts. Every planned check
  must then reach exactly one terminal result (`plan_closure`), and the
  recorded plan must equal the one the manifest implies
  (`plan_matches_manifest`).
- **A witness that each PASS could have failed.** Before a check's PASS is
  accepted, the same checker is run, in memory, on a known-bad copy of its
  own input: a dropped row, a duplicated row, a deleted accepted row, a
  shifted stored value, a missing reviewer, a shifted timestamp, a retracted
  citation. The PASS stands only if that case was rejected (WITNESSED). A
  checker that accepts the bad case is a proven blind spot (FAIL); one with
  no case to try is not trusted (ABSTAIN). The witness invocations are in the
  ledger (`pass_requires_falsifier_witness`).
- **Controls that held.** A must-fail canary (a planted duplicate row) has
  to fail and its must-pass twin has to pass (`canary_controls_hold`). The
  decimal comparator is re-tested on three known pairs
  (`comparator_self_test`).
- **Untouched evidence.** The manifest, inputs, documents and check modules
  are pinned before the plan and re-hashed after the last check; a write to
  any of them during the run fails it, even if the original bytes were put
  back (`harness_pins_intact`).
- **Real rows.** `rows_examined` counts distinct data rows of declared inputs
  read by an executed check. Comparisons, events, verdicts and citations are
  never rows, so a header-only file gives 0 and cannot PASS.
- **No unexplained gaps.** A required check that did not execute is FAIL
  (PARTIAL_EXECUTION) unless it records one of a closed set of
  justifications (for example EMPTY_POPULATION or NOT_DECLARED), which
  abstains instead and never passes.
- **Discrimination above zero.** A numeric check that reports how much of its
  input space it could have rejected (its discrimination) cannot PASS at 0.

## Quick start

From a source checkout, with no installation:

```sh
# POSIX shell
export PYTHONPATH=src
python -m science_gate.cli demo
python -m science_gate.cli init my-project
python -m science_gate.cli verify my-project/manifest.json --output my-run
python -m science_gate.cli report my-run
```

```powershell
# PowerShell
$env:PYTHONPATH = "src"
python -m science_gate.cli demo
```

Installed (`pip install .`), the same commands are available as
`science-gate demo`, `science-gate verify ...` and so on.

`demo` copies the bundled synthetic fixtures into a new directory (a fresh
temporary directory unless `--output DIR` is given), runs every command
against them, and prints a table of expected against actual results: a valid
run with every PASS witnessed, the canary pair and the plan; an empty input;
a narrated citation log; a GRIM-inconsistent mean; a narrated number; a
resolver whose canary resolves; agent assertions joined to a sealed ledger;
mutation testing with its forced detection and conservation checks; staleness
and witnessed revalidation; and controlled-local packaging. It exits 0 only
if every expectation holds. [examples/](examples/README.md) walks through one
runnable project step by step.

## Commands

| Command | What it does |
|---|---|
| `init PATH` | Writes a synthetic starter project into an empty or new directory. |
| `verify MANIFEST [--output DIR] [--live] [--require-signature]` | Verifies a manifest and writes a run directory (default `./science-gate-runs/<run_id>/`). An existing non-empty `--output` is refused (`OUTPUT_EXISTS`, exit 3). |
| `report RUN_DIR [--require-signature]` | Re-verifies a run directory's receipt, ledger chain, recorded figures and stored exports (the `run.json` and `results.sarif` validators, and `results.sarif` re-derived from `run.json`), then re-renders `report.md` and `report.html`. A directory without `run.json`, or named `*.incomplete`, is `RUN_INCOMPLETE` (ERROR, exit 3). |
| `mutate MANIFEST [--output DIR] [--harness]` | Injects 21 known defects (after a forced-detection control, M00) into copies of an accepted evidence tree and records which ones the verifier caught, for the right reason, and at which stage a missed one stopped mattering. `--harness` also mutates the harness itself (H01 to H07) and writes `harness-report.json` and `harness-report.md` beside the mutation report. |
| `impact ARTIFACT_ID --manifest MANIFEST` | Marks an artifact and its descendants in the dependency graph `STALE_PENDING_REVALIDATION`. |
| `revalidate ARTIFACT_ID --manifest MANIFEST [--witness PATH]` | Re-hashes an artifact. A root artifact is `REVALIDATED_UNCHANGED` (descendants stale only because of it are cleared) or `REVALIDATED_CHANGED` (descendants stay stale). A derived artifact is revalidated as unchanged only with a recompute witness (`--witness`) that started after its change; re-hashing alone is refused as `REFUSED_VACUOUS_CUTOFF`. |
| `what-if ARTIFACT_ID --manifest MANIFEST` | Gives an artifact a synthetic change in memory and checks that staleness detection marks every descendant and would block publication. Writes nothing. |
| `package MANIFEST --output PATH [--force]` | Builds an evaluation package for local re-execution. Controlled data is never copied; only its digest and retrieval instructions are. |
| `demo [--output DIR]` | Runs the self-checking synthetic demonstration. |

Every command prints a one-line status headline first, then the paths it
wrote. Exit codes:

| Exit | Status | Meaning |
|---|---|---|
| 0 | PASS | Every declared expectation held, with evidence that each check could have failed. |
| 1 | FAIL | A required check or an invariant found a definite contradiction, or a check or control was shown to miss a known defect. |
| 2 | ABSTAIN | Something was missing, empty, skipped, unavailable, unverified or untestable. |
| 3 | ERROR | The manifest was invalid or unsafe, an argument was wrong, an export failed its validator, the tool itself failed, or `--require-signature` was given and the receipt's HMAC-SHA256 authenticator did not verify. |

Argument errors exit 3, never 2, so that 2 always means ABSTAIN. A standard
output that stops accepting lines (a reader that leaves early, as in
`science-gate demo | head -1`) also exits 3, with one line on standard error
naming the cause, never with a traceback or with Python's own exit 1, which
would read as FAIL.

A `verify` run directory holds `run.json`, `report.md`, `ledger.jsonl`,
`evidence-manifest.json`, `receipt.json`, `receipt.auth.json`,
`results.sarif` and `report.html`. The directory is written all or nothing:
the files go into a staging sibling `.<name>.incomplete` that is renamed into
place only after every file is written and every export has passed its
validator. `report.md` opens with these headings, in order: STATUS, WHAT WAS
EXPECTED, WHAT WAS EXAMINED, WHAT ACTUALLY RAN, WHAT PASSED, WHAT FAILED,
WHAT ABSTAINED, WHAT REMAINS UNRESOLVED, WHAT THIS RESULT DOES NOT PROVE. It
names the run's row figure exactly once, as `rows_examined`.

## Check kinds

`row_count`, `required_columns`, `duplicate_rows`, `snapshot_completeness`,
`numeric_agreement`, `reviewer_protocol`, `time_source`,
`summary_consistency`, `verification_log`, `citation_resolver`,
`citation_metadata`, `claim_registry` and `dependency_currency`, plus:

- `editorial_status`: retractions, reinstatements, corrections and
  expressions of concern for cited DOIs, from at least two independent
  editorial channels; an aggregator's flag is never counted as a channel.
- `claim_join`: joins agent or pipeline assertions ("tests ran", "file
  checked") to a sealed ledger. Each is BACKED, NARRATED (no such invocation,
  or an impossible timeline), CONTRADICTED (the ledger records a different
  result) or, for an uncited failing invocation, ORPHANED.
- `mutation_accounting`: re-checks a mutation report's bookkeeping, so a
  report that drops a mutant from its counts fails.

`claim_registry` also runs GRIM, GRIMMER and DEBIT consistency tests on
declared means, SDs and proportions, recomputes derived numbers from both
the printed and the stored operands (a number that reproduces only the
printed ones is a narrated number), fingerprints which rounding rule
produced a printed value, and reports how many of the manuscript's numbers
it actually checked.

## States

- **Status**: `PASS`, `FAIL`, `ABSTAIN`, `ERROR`. When several findings
  apply, the status is the highest of ERROR, FAIL, ABSTAIN, PASS, and a run
  with nothing to judge is ABSTAIN (INSUFFICIENT_EVIDENCE), never PASS.
- **Reason**: `VERIFIED`, `UNVERIFIED`, `INVALID_BASELINE`, `BLIND_SPOT`,
  `INSUFFICIENT_EVIDENCE`, `SOURCE_UNAVAILABLE`, `SOURCE_MISMATCH`,
  `PROTOCOL_BROKEN`, `PARTIAL_EXECUTION`, `OUT_OF_SCOPE`,
  `REQUIRES_HUMAN_REVIEW`, `PROTOCOL_DRIFT`, `HARNESS_BLIND`,
  `UNMEASURED_MUTANTS`. `BLIND_SPOT` is FAIL when a miss is proven (a
  checker or canary accepted known-bad input) and ABSTAIN when coverage is
  unknown (no witness could be built).
- **Failure modes**: `VACUOUS_PASS`, `NARRATED_VERIFICATION`,
  `PARTIAL_EXECUTION`, `DEFECTIVE_VERIFICATION`, `OMITTED_POPULATION`,
  `SOURCE_MISMATCH`, `PROTOCOL_DRIFT`, `EPHEMERAL_CLAIM`, `STALE_DEPENDENCY`,
  `VACUOUS_CUTOFF`.
- **Check execution**: `CHECKED`, `SKIPPED`, `NOT_APPLICABLE`. A skipped or
  not-applicable check records a justification: `EMPTY_POPULATION`,
  `INPUT_UNAVAILABLE`, `SOURCE_REJECTED`, `EVIDENCE_MALFORMED`,
  `NOT_DECLARED`, `NO_DISCRIMINATION` or `GUARDED_ELSEWHERE`. Each check runs
  inside a ledger invocation whose result is `STARTED` and then one of
  `COMPLETED`, `ERRORED` or `ABSTAINED`; the ledger opens with one `PLAN`
  entry.
- **Falsifier witness**: `WITNESSED`, `REFUTED`, `UNWITNESSED`, `NO_CASE`,
  `NO_GENERATOR`; each case is `REJECTED`, `ACCEPTED` or `INCONCLUSIVE`.
- **Input states**: `PARSED`, `PARTIAL`, `EMPTY`, `MISSING`, `REFUSED`,
  `OPEN_FAILED`, `PARSE_ERROR`, `HASH_MISMATCH`. Only `PARSED` counts as
  complete.
- **Numeric tests**: `CONSISTENT`, `INCONSISTENT`, `VACUOUSLY_CONSISTENT`,
  `NOT_TESTABLE`; rounding conventions `HALF_EVEN`, `HALF_UP`, `TRUNCATE`,
  `CEILING`, `FLOOR`, `FLOAT_FIRST`. Ratios are `DEFINED`,
  `ZERO_DENOMINATOR` or `UNAVAILABLE`; 0/0 never becomes 0% or 100%.
- **Dependency validity**: `CURRENT`, `STALE_PENDING_REVALIDATION`,
  `REVALIDATED_UNCHANGED`, `REVALIDATED_CHANGED`, `SUPERSEDED`,
  `INVALIDATED`, `UNRESOLVED`. A stale node records whether an upstream
  artifact (`UPSTREAM`) or a check that backed it (`VERIFIER`) changed.
- **Citations**: resolver states `DOI_RESOLVED`,
  `DOI_NOT_RESOLVED_AT_CAPTURE`, `DOI_TARGET_MISMATCH`,
  `SOURCE_UNAVAILABLE`; metadata states `VERIFIED_WITHIN_DECLARED_SCOPE`,
  `FIELD_MISMATCH`, `CONFLATED_ENTRY`,
  `RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES`; editorial statuses
  `NOT_RETRACTED_WITHIN_SCOPE`, `RETRACTED`, `REINSTATED`, `CORRECTED`,
  `EXPRESSION_OF_CONCERN`, `UNDETERMINED`.
- **Assertions**: `BACKED`, `NARRATED`, `CONTRADICTED`, `ORPHANED`.
- **Mutations**: `DETECTED`, `BLIND_SPOT`, `VERIFIER_ERROR`, `TIMED_OUT`,
  `FLAKY` (executed); `NOT_ACTIVATED`, `NOOP_MUTATION`,
  `CANONICALLY_EQUIVALENT`, `DUPLICATE_MUTANT`, `SUPPRESSED`, `SKIPPED`,
  `NOT_APPLICABLE` (not executed, never counted as detections). A blind spot
  records where the defect stopped mattering: `NOT_READ`,
  `READ_NOT_INFECTED`, `INFECTED_NOT_PROPAGATED`, `PROPAGATED_NOT_CHECKED`.
- **Receipt authentication**: `receipt.json` is the bare statement, signed or
  not; `receipt.auth.json` says `UNSIGNED` or holds an HMAC-SHA256 shared-key
  authenticator (when `SCIENCE_GATE_HMAC_KEY_FILE` names a readable key
  file). Re-checking gives `UNSIGNED`, `SIGNED_VERIFIED`, `SIGNED_FAILED` or
  `SIGNED_UNCHECKED` (no key to check with).
- **Access classes**: `PUBLIC`, `REFERENCE_ONLY`, `SYNTHETIC`,
  `CONTROLLED_LOCAL`. A manifest that declares no corpus is treated as
  `CONTROLLED_LOCAL`.

Missing evidence is never turned into zero, false, PASS or "no defects". An
unknown count is `null` in JSON and "unknown" in reports.

## What passing does not prove

A PASS shows that the declared checks had the opportunity to fail on the
declared inputs, were each seen to reject at least one known-bad case, and
did not fail. It does not show:

- that the conclusion, measurement or model is scientifically valid, accurate,
  safe or fit for any use;
- anything about inputs, checks or questions that the manifest did not
  declare;
- that the declared expectations (expected rows, claimed values, accepted
  snapshots, required reviewers) were the right ones;
- that a check catches every defect: a falsifier witness shows it rejected
  one known-bad case of a known kind, and a canary shows one control
  behaved;
- that an analysis was actually re-run: stored outputs are compared by
  digest and value, analysis recipes, code versions and environments are
  recorded as declared, not executed, and a recompute witness is a document
  checked for consistency, not looked up in any ledger;
- that a number is right because it is GRIM-, GRIMMER- or DEBIT-consistent:
  those tests can only show that some reported numbers cannot all be true;
- that a citation is correct beyond the fields compared against the frozen
  (or, with `--live`, freshly retrieved) record, or that a work is not
  retracted beyond the editorial channels that were consulted;
- that a BACKED assertion is true beyond what its cited invocation recorded,
  or that a sealed run's seal was not rebuilt by someone who rewrote the
  whole chain (only the receipt and its authenticator guard that);
- that nothing changed evidence outside the process: the write-detection
  hook does not see subprocesses or C extensions;
- that an UNSIGNED receipt was not rewritten by someone who could edit the run
  directory, or that an HMAC authenticator was produced by anyone in
  particular (anyone holding the key can produce one);
- that a mutation-testing sensitivity figure generalizes beyond the injected
  defect types and the one evidence tree it was measured on.

## Determinism and safety

- Output is byte-identical across `PYTHONHASHSEED` values under a fixed clock
  (`SCIENCE_GATE_FIXED_TIME=2026-01-02T03:04:05Z`, ISO-8601 UTC with `Z`).
  Identifiers (`run-`, `inv-`, `mut-`, `har-`, `wif-`, `wit-`) derive from
  content hashes, never from random numbers.
- Canonical JSON sorts keys by Unicode code point, refuses floats and
  integers beyond ±(2^53 − 1), and is pinned by golden vectors. It is not
  RFC 8785.
- Every write goes through one safe-write function that refuses any path
  resolving outside its root.
- Values that look like credentials, and the values of secret-named
  environment variables, are redacted before they are recorded.
- One process-wide audit hook is installed once and records only while a run
  is recording; nothing else is hooked, and no process is started.

See [SECURITY.md](SECURITY.md) for the threat model and how to report a
problem, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the binding
design contract (section 17 covers the frontier extensions).

## Development

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests
```

`tests/test_required.py` holds one test per numbered requirement (r01 to
r28). See [CONTRIBUTING.md](CONTRIBUTING.md).

GitHub Actions runs this suite and the self-checking demonstration on Python
3.11, 3.12 and 3.13 for pull requests and pushes to `main`. A run with no
discovered tests or no completed passing tests fails. Skips remain visible in
the test output; they are never counted as passing tests. A CodeQL workflow
(the organization's SHA-pinned reusable workflow) analyses the Python code and
the workflow files on the same events and weekly.

## License status

No license has been chosen. The license field in `pyproject.toml` is
`NOASSERTION`, there is no LICENSE file, and no author list is recorded.

All fixtures and examples are synthetic: invented sample ids, sites,
reviewers, authors, journals, assertions and values, with DOIs under the
`10.5555` test prefix. None of them reports a real finding.

## Relation to the estate

Part of the [SZL Holdings](https://github.com/szl-holdings) GitHub estate; models, datasets and Spaces are published under the [SZLHOLDINGS](https://huggingface.co/SZLHOLDINGS) Hugging Face org.


## Live product: SZL Science Gate Studio (synthetic-only)

The [Studio source and release contract](studio/README.md) provide an
interactive Gradio application built over the **real** scientific-evidence-gate
engine, not a screenshot or an independently implemented scoring demo.
Visitors can run six source-bundled synthetic scenarios and download original
verifier receipts, check outcomes and a reproducibility ZIP. A Lutar arithmetic
panel is deliberately marked as WHAT-IF rather than as live authenticated
release evidence. Deployment is to a source-pinned CPU-only HF Space; exact
GitHub protected main remains the sole application source.

**No biological data, model training, independent validation, or production
release is represented by this public synthetic tool.**
