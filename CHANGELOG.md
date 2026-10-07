# Changelog

All notable changes to this project are recorded here. Versions follow the
`version` field in `pyproject.toml`.

## 0.1.0 (unreleased)

First version. Everything below is new.

### Added

- Manifest format `science-gate-manifest/v1` with strict validation: unknown
  keys, unsafe subprocess keys, duplicate paths, unsafe paths and malformed
  JSON are named ERROR findings, never tracebacks. Optional
  `corpus.source_licenses` and `corpus.approved_redactions` are recorded as
  declared.
- Input discovery and accounting with per-input row closure against an
  INDEPENDENT `expected_rows`, streamed SHA-256 digests and strict CSV, JSON
  and JSON Lines parsing.
- A hash-chained execution ledger: every check is a STARTED entry and a
  terminal entry, sealed with a head digest and a length.
- The verification engine with thirteen check kinds, ten named invariants and
  the PASS contract of ARCHITECTURE.md section 6 (the frontier extensions
  below add three check kinds and six invariants).
- Claims (`claim_registry`), citations (`verification_log`,
  `citation_resolver`, `citation_metadata`, frozen and live adapters) and
  dependency currency (`dependency_currency`, `impact`, `revalidate`).
- Run directories: `run.json`, `report.md`, `ledger.jsonl`,
  `evidence-manifest.json`, `receipt.json` (UNSIGNED or HMAC-SHA256),
  `results.sarif` and the self-contained `report.html`; `report RUN_DIR`
  re-verifies and re-renders them.
- Mutation testing with twenty operators (twenty-one with
  `M21_removed_plan`, below), writing `mutation-report.json`,
  `mutation-report.md` and `mutation-report.html`.
- Evaluation packaging that never copies CONTROLLED_LOCAL or REFERENCE_ONLY
  data.
- The self-checking `demo` command, the `examples/field-survey` project, and
  bundled fixtures and schemas as package data.
- Tests for the 28 numbered requirements, security (section 15) and
  determinism (section 16).

### Added: frontier extensions (ARCHITECTURE.md section 17)

- Falsifier witnesses: before a PASS is accepted, its checker runs in
  memory on a known-bad copy of its own input, in its own ledger invocation;
  every PASS must be WITNESSED (`pass_requires_falsifier_witness`). A
  must-fail and must-pass canary pair and a comparator self-test run as
  controls on every verify.
- A PLAN entry opens every ledger, committing to the inputs, checks,
  parameter and checker digests and pinned files before any check runs
  (`plan_closure`, `plan_matches_manifest`); `ledger.reseal` replays what a
  thorough forger would do.
- Harness pins and one process-wide, context-gated audit hook: evidence files
  and check modules are pinned and re-hashed, and any write to them during a
  run fails it (`harness_pins_intact`).
- A verdict lattice with a recorded transition log, typed `Ratio` values
  (0/0 is never 0% or 100%), closed-vocabulary skip justifications, and
  `run.json` `controls` (plan, falsifiers, canary, comparator, pins,
  minimum discrimination, claim-join counts, verdict transitions).
- Numeric forensics (`science_gate.numeric`): GRIM, GRIMMER, DEBIT, metric
  feasibility, derived intervals and tolerance comparison, each with its
  discrimination; narrated-number and rounding-rule fingerprint checks in
  `claim_registry`; a numeric coverage funnel with a `coverage_floor`; the
  `EITHER_HALF` rounding rule for third-party numbers.
- Mutation testing v2: the M00 forced-detection control, operator
  `M21_removed_plan`, one status per mutant with conservation identities,
  activation and PIE-stage attribution of blind spots, the
  `mutation_accounting` check kind, and harness self-mutation
  (`mutate --harness`, H01 to H07).
- Witnessed revalidation: a derived artifact is revalidated as unchanged only
  with a recompute witness that started after its change
  (`revalidate --witness`); re-hashing alone is refused as
  `REFUSED_VACUOUS_CUTOFF`. Verifier drift through `backed_by_checks`, and
  the `what-if` command.
- Resolver negative controls (per-prefix canary DOIs; Handle body codes
  decide resolution), impossible-timeline detection, and the
  `editorial_status` check kind over at least two editorial channels.
- The `claim_join` check kind: assertions joined to a sealed ledger as
  BACKED, NARRATED, CONTRADICTED or ORPHANED.
- Exporters that can fail: validators for `run.json`, `results.sarif` and
  `report.md` run before anything is written and again on `report RUN_DIR`;
  run directories are finalized atomically from a staging sibling.
- Receipts are a bare statement (`receipt.json`) plus an authentication
  sidecar (`receipt.auth.json`); AuthStatus `UNSIGNED`, `SIGNED_VERIFIED`,
  `SIGNED_FAILED`, `SIGNED_UNCHECKED`; `verify` and `report` accept
  `--require-signature` (exit 3 unless verified). Canonical JSON refuses
  integers beyond ±(2^53 − 1) and is pinned by golden vectors; it is not
  RFC 8785.
- The demo now also shows falsifier witnesses and the canary pair, the PLAN,
  a GRIM inconsistency, a narrated number, a resolving resolver canary, the
  claim-join buckets, M00 and conservation, M21 caught by `plan_closure`,
  and witnessed revalidation (31 expectations).

### Changed by the frontier extensions

- `rows_examined` counts only distinct data rows of declared inputs read by
  an executed check; a header-only input gives 0.
- A required check that did not execute without a recorded justification is
  FAIL / PARTIAL_EXECUTION (decision D1); a justified one abstains.
- `BLIND_SPOT` is also a check and run reason: FAIL for a proven miss,
  ABSTAIN when coverage is unknown.
- `report.md` names the run's row figure once, as `rows_examined`; a
  check's own figure is "subject records examined".
- Packages carry `expected/receipt.auth.json` beside `expected/receipt.json`.

### Not established

No version of this tool establishes scientific truth, accuracy, safety, or
fitness for use.
