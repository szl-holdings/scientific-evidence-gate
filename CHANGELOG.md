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
  the PASS contract of ARCHITECTURE.md section 6.
- Claims (`claim_registry`), citations (`verification_log`,
  `citation_resolver`, `citation_metadata`, frozen and live adapters) and
  dependency currency (`dependency_currency`, `impact`, `revalidate`).
- Run directories: `run.json`, `report.md`, `ledger.jsonl`,
  `evidence-manifest.json`, `receipt.json` (UNSIGNED or HMAC-SHA256),
  `results.sarif` and the self-contained `report.html`; `report RUN_DIR`
  re-verifies and re-renders them.
- Mutation testing with twenty operators, writing `mutation-report.json`,
  `mutation-report.md` and `mutation-report.html`.
- Evaluation packaging that never copies CONTROLLED_LOCAL or REFERENCE_ONLY
  data.
- The self-checking `demo` command, the `examples/field-survey` project, and
  bundled fixtures and schemas as package data.
- Tests for the 28 numbered requirements, security (section 15) and
  determinism (section 16).

### Not established

No version of this tool establishes scientific truth, accuracy, safety, or
fitness for use.
