# Security

scientific-evidence-gate reads files that other people prepared: manifests,
data files, citation logs, dependency graphs. It treats every one of them as
untrusted. This file describes what it protects against, what it does not,
and how to report a problem.

## Reporting a problem

The project is unreleased and local-only. Report a suspected vulnerability
privately to the repository owner, not in a public issue or pull request.
Include the manifest or file that triggers it (synthetic, please; never real
credentials or controlled data), the command, the exit code and the output.

## What the tool protects against

Each item below has tests in `tests/test_security.py` (ARCHITECTURE.md
section 15) and, where noted, elsewhere.

- **Path traversal.** Declared paths are relative to the manifest's
  directory. `..`, absolute paths, drive letters, Windows device names and
  NUL bytes are refused before any file is opened.
- **Symlink escape.** A path that resolves outside the manifest directory
  through a symbolic link or a Windows directory junction is refused. Where
  the operating-system account cannot create symbolic links, those tests are
  skipped with a visible reason, never passed silently; the junction tests
  need no privilege and run on Windows.
- **Duplicate manifest paths.** Two entries naming the same file (compared
  case-insensitively on Windows) are refused as `DUPLICATE_PATH`.
- **Oversized input and unexpected file count.** Files larger than
  `limits.max_file_bytes`, inputs beyond `limits.max_files` and records beyond
  `limits.max_rows` are refused or deferred and reported, never silently
  truncated. Numbers longer than 100 characters, including JSON values with
  huge exponents, are refused without being expanded.
- **Malformed JSON.** A manifest that cannot be parsed is an ERROR with
  `MALFORMED_JSON`, never a traceback. JSON inputs reject duplicate keys,
  `NaN` and `Infinity`.
- **Hash mismatch.** A declared SHA-256 that does not match the bytes on disk
  makes the input `HASH_MISMATCH` and the run FAIL.
- **Subprocess requests.** A manifest key named `command`, `cmd`, `shell`,
  `exec`, `script`, `run`, `subprocess` or `entrypoint`, at any depth, is
  refused as `UNSAFE_SUBPROCESS_REQUEST`. The package never starts a process
  and never builds one from input text.
- **Secret leakage.** Values with known credential shapes (private-key
  blocks, common provider token prefixes, JWTs, `password=...` assignments)
  and the values of secret-named environment variables (8 characters or
  more) are replaced with `[REDACTED]` before evidence is recorded or
  written.
- **Writes outside the output directory.** Every write goes through
  `science_gate._safeio.safe_write`, which refuses any path that resolves
  outside its root. `package` refuses an output inside the evaluated
  project, and `--force` replaces only a previous package whose every file it
  listed itself.
- **Half-written run directories.** `verify` writes into a staging sibling
  `.<name>.incomplete` and renames it into place only after every file is
  written and every export has passed its validator, so an interrupted run
  (a full disk, for example) never leaves a `report.md` without its
  `run.json`. An existing non-empty `--output` is refused (`OUTPUT_EXISTS`),
  and `report` refuses a directory without `run.json` as `RUN_INCOMPLETE`.
- **Writes to evidence during a run.** The files a run depends on (manifest,
  inputs, role documents, check modules) are pinned before the run's PLAN and
  re-hashed after the last check. One process-wide audit hook, active only
  while a run records, also reports any write, rename or delete of a pinned
  path, so a write that restores the original bytes is still caught
  (`harness_pins_intact`). The hook cannot see I/O done by subprocesses or C
  extensions.
- **Hidden characters in the source.** No Python file in `src/` or `tests/`
  may hold a carriage return or a character a reviewer cannot see or would
  mistake for another: bidirectional and other format controls, zero-width
  characters, look-alike spaces. A literal that needs one is written as an
  escape (the "Trojan Source" class of attack).
- **Network.** Live citation lookups run only with `--live` or
  `citations.live: true`, through `urllib` with a 10-second timeout. Any
  network error or non-2xx response becomes `SOURCE_UNAVAILABLE`. Tests
  inject a failing opener and never touch the network.

## What it does not protect against

- **A credential in an unrecognized form.** Redaction knows specific shapes
  and the values of secret-named environment variables. A secret in any other
  form is not recognized and could appear in evidence or reports.
- **Rewritten run directories.** An UNSIGNED receipt's content hash detects
  accidental change, but anyone who can edit the run directory can rewrite
  and rehash it. Set `SCIENCE_GATE_HMAC_KEY_FILE` to a key file to
  authenticate receipts with an HMAC-SHA256 shared-key authenticator, written
  to `receipt.auth.json` beside the statement; the key itself is never
  written. Anyone holding the key can produce the authenticator, so it is not
  a public signature. Pass `--require-signature` to make anything short of a
  verified authenticator exit 3.
- **Forged but consistent inputs.** The tool checks that evidence is
  internally consistent and matches declared digests. It cannot tell whether
  the declared digests, snapshots or expectations were honest.
- **Resource exhaustion beyond the declared limits.** Limits bound what is
  read, but a manifest may declare generous limits.
- **Scientific validity.** No output of this tool establishes scientific
  truth, accuracy, safety, or fitness for use.
