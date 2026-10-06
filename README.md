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
  row accounting, a hash-chained execution ledger)?
- Did every declared check run, reach a terminal result, and examine at least
  one row?
- Do recorded values, citations, claims, reviews, timestamps and dependency
  states agree with each other, under the declared rules?

It does not answer whether a conclusion is true. Every output keeps three
kinds of evidence apart:

| Boundary | Meaning | Established here? |
|---|---|---|
| Integrity | Was this the exact artifact, input, execution and version claimed? | Yes, within the declared scope |
| Performance | How did the fixed system behave on the declared evaluation? | Yes, for that one evaluation |
| Scientific validity | Does the conclusion hold in its intended domain? | **Never** |

Every run receipt carries this sentence, verbatim:

> A receipt supports integrity, provenance, and replayability. It does not establish scientific truth, accuracy, safety, or fitness for use.

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
against them, and prints a table of expected against actual results. It
exits 0 only if every expectation holds. [examples/](examples/README.md)
walks through one runnable project step by step.

## Commands

| Command | What it does |
|---|---|
| `init PATH` | Writes a synthetic starter project into an empty or new directory. |
| `verify MANIFEST [--output DIR] [--live]` | Verifies a manifest and writes a run directory (default `./science-gate-runs/<run_id>/`). |
| `report RUN_DIR` | Re-verifies a run directory's receipt, ledger chain and recorded figures, then re-renders `report.md` and `report.html`. |
| `mutate MANIFEST [--output DIR]` | Injects 20 known defects into copies of an accepted evidence tree and records which ones the verifier caught, for the right reason. |
| `impact ARTIFACT_ID --manifest MANIFEST` | Marks an artifact and its descendants in the dependency graph `STALE_PENDING_REVALIDATION`. |
| `revalidate ARTIFACT_ID --manifest MANIFEST` | Re-hashes an artifact: `REVALIDATED_UNCHANGED` (descendants stale only because of it are cleared) or `REVALIDATED_CHANGED` (descendants stay stale). |
| `package MANIFEST --output PATH [--force]` | Builds an evaluation package for local re-execution. Controlled data is never copied; only its digest and retrieval instructions are. |
| `demo [--output DIR]` | Runs the self-checking synthetic demonstration. |

Every command prints a one-line status headline first, then the paths it
wrote. Exit codes:

| Exit | Status | Meaning |
|---|---|---|
| 0 | PASS | Every declared expectation held, with evidence that each check could have failed. |
| 1 | FAIL | A required check or an invariant found a definite contradiction. |
| 2 | ABSTAIN | Something was missing, empty, skipped, unavailable or unverified. |
| 3 | ERROR | The manifest was invalid or unsafe, an argument was wrong, or the tool itself failed. |

Argument errors exit 3, never 2, so that 2 always means ABSTAIN.

A `verify` run directory holds `run.json`, `report.md`, `ledger.jsonl`,
`evidence-manifest.json`, `receipt.json`, `results.sarif` and `report.html`.
`report.md` opens with these headings, in order: STATUS, WHAT WAS EXPECTED,
WHAT WAS EXAMINED, WHAT ACTUALLY RAN, WHAT PASSED, WHAT FAILED, WHAT
ABSTAINED, WHAT REMAINS UNRESOLVED, WHAT THIS RESULT DOES NOT PROVE.

## States

- **Status**: `PASS`, `FAIL`, `ABSTAIN`, `ERROR`. Precedence when several
  findings apply: ERROR, then FAIL, then ABSTAIN, then PASS.
- **Reason**: `VERIFIED`, `UNVERIFIED`, `INVALID_BASELINE`, `BLIND_SPOT`,
  `INSUFFICIENT_EVIDENCE`, `SOURCE_UNAVAILABLE`, `SOURCE_MISMATCH`,
  `PROTOCOL_BROKEN`, `PARTIAL_EXECUTION`, `OUT_OF_SCOPE`,
  `REQUIRES_HUMAN_REVIEW`.
- **Failure modes**: `VACUOUS_PASS`, `NARRATED_VERIFICATION`,
  `PARTIAL_EXECUTION`, `DEFECTIVE_VERIFICATION`, `OMITTED_POPULATION`,
  `SOURCE_MISMATCH`, `PROTOCOL_DRIFT`, `EPHEMERAL_CLAIM`, `STALE_DEPENDENCY`.
- **Check execution**: `CHECKED`, `SKIPPED`, `NOT_APPLICABLE`. Each check
  runs inside a ledger invocation whose result is `STARTED` and then one of
  `COMPLETED`, `ERRORED` or `ABSTAINED`.
- **Input states**: `PARSED`, `PARTIAL`, `EMPTY`, `MISSING`, `REFUSED`,
  `OPEN_FAILED`, `PARSE_ERROR`, `HASH_MISMATCH`. Only `PARSED` counts as
  complete.
- **Dependency validity**: `CURRENT`, `STALE_PENDING_REVALIDATION`,
  `REVALIDATED_UNCHANGED`, `REVALIDATED_CHANGED`, `SUPERSEDED`,
  `INVALIDATED`, `UNRESOLVED`.
- **Citations**: resolver states `DOI_RESOLVED`,
  `DOI_NOT_RESOLVED_AT_CAPTURE`, `DOI_TARGET_MISMATCH`,
  `SOURCE_UNAVAILABLE`; metadata states `VERIFIED_WITHIN_DECLARED_SCOPE`,
  `FIELD_MISMATCH`, `CONFLATED_ENTRY`,
  `RECORD_NOT_FOUND_UNDER_RECORDED_QUERIES`.
- **Receipt signature**: `UNSIGNED` or `SIGNED_HMAC_SHA256` (when
  `SCIENCE_GATE_HMAC_KEY_FILE` names a readable key file).
- **Access classes**: `PUBLIC`, `REFERENCE_ONLY`, `SYNTHETIC`,
  `CONTROLLED_LOCAL`. A manifest that declares no corpus is treated as
  `CONTROLLED_LOCAL`.

Missing evidence is never turned into zero, false, PASS or "no defects". An
unknown count is `null` in JSON and "unknown" in reports.

## What passing does not prove

A PASS shows that the declared checks had the opportunity to fail on the
declared inputs and did not. It does not show:

- that the conclusion, measurement or model is scientifically valid, accurate,
  safe or fit for any use;
- anything about inputs, checks or questions that the manifest did not
  declare;
- that the declared expectations (expected rows, claimed values, accepted
  snapshots, required reviewers) were the right ones;
- that an analysis was actually re-run: stored outputs are compared by
  digest and value, and analysis recipes, code versions and environments are
  recorded as declared, not executed;
- that a citation is correct beyond the fields compared against the frozen
  (or, with `--live`, freshly retrieved) record;
- that an UNSIGNED receipt was not rewritten by someone who could edit the run
  directory;
- that a mutation-testing sensitivity figure generalizes beyond the injected
  defect types and the one evidence tree it was measured on.

## Determinism and safety

- Output is byte-identical across `PYTHONHASHSEED` values under a fixed clock
  (`SCIENCE_GATE_FIXED_TIME=2026-01-02T03:04:05Z`, ISO-8601 UTC with `Z`).
  Identifiers derive from content hashes, never from random numbers.
- Every write goes through one safe-write function that refuses any path
  resolving outside its root.
- Values that look like credentials, and the values of secret-named
  environment variables, are redacted before they are recorded.

See [SECURITY.md](SECURITY.md) for the threat model and how to report a
problem, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the binding
design contract.

## Development

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests
```

`tests/test_required.py` holds one test per numbered requirement (r01 to
r28). See [CONTRIBUTING.md](CONTRIBUTING.md).

## License status

No license has been chosen. The license field in `pyproject.toml` is
`NOASSERTION`, there is no LICENSE file, and no author list is recorded.

All fixtures and examples are synthetic: invented sample ids, sites,
reviewers, authors, journals and values, with DOIs under the `10.5555` test
prefix. None of them reports a real finding.
