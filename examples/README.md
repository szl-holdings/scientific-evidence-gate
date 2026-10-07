# Examples

`field-survey/` is one small, runnable project. Everything in it is
synthetic: six invented survey plots (`PLOT-SYN-01` to `PLOT-SYN-06`) in
invented habitats, two invented reviewers and two invented field visits. The
numbers mean nothing. They were chosen to exercise the rules, not to describe
anything real.

The commands below run from the repository root without installing anything.
If the package is installed, `science-gate` replaces
`python -m science_gate.cli`.

```sh
export PYTHONPATH=src            # PowerShell: $env:PYTHONPATH = "src"
```

## 1. What the project declares

`field-survey/manifest.json` declares:

- one required input, `data/plots.csv`, with its SHA-256 and an INDEPENDENT
  expectation of 6 rows (`expected_rows` plus `denominator_source`);
- an accepted snapshot, `snapshots/accepted.json`, holding a digest of every
  accepted row;
- a review protocol with two required reviewers (`reviews/verdicts.json`);
- time sources: two observations, each with its local time, a fixed UTC
  offset and the normalized UTC (`time/events.json`);
- eight required checks: `row_count`, `required_columns`, `duplicate_rows`,
  `snapshot_completeness`, two `numeric_agreement` checks, `reviewer_protocol`
  and `time_source`;
- a SYNTHETIC corpus with default permissions.

Two of the declared values show the numeric rules at work:

- `canopy` claims `41.2` for `PLOT-SYN-01`, whose stored value is `41.25`.
  Rounded half-even to the one decimal the claim prints, the stored value is
  `41.2`, so the claim agrees at its stated precision. A claim of `41.3`
  would disagree; rounding never makes two different printed values agree.
- `stems` declares `thousands: ","`, so the stored `"3,042"` equals the
  claimed `3,042`. Without the declaration, `"3,042"` would be ambiguous and
  need human review.

## 2. Verify it

```sh
python -m science_gate.cli verify examples/field-survey/manifest.json --output field-run
```

Expected: exit code 0 and a headline such as

```
PASS (VERIFIED) run-...: 8/8 required checks executed, 6 rows examined, 1/1 inputs opened
```

followed by the eight files written into `field-run/`. The six rows are the
plot rows: `rows_examined` counts distinct data rows of declared inputs, so
reviewer verdicts and time events are never counted as rows. Every PASS in
`field-run/run.json` carries `"falsification": "WITNESSED"`: before the PASS
was accepted, its checker was run on a known-bad copy of its own input (a
dropped row, a shifted value, a missing reviewer) and rejected it. The
ledger's first entry is the run's PLAN, and the controls block shows the
must-fail canary failing and its must-pass twin passing. Open
`field-run/report.md`: it starts with STATUS and walks through WHAT WAS
EXPECTED, WHAT WAS EXAMINED, WHAT ACTUALLY RAN, and so on, ending with WHAT
THIS RESULT DOES NOT PROVE. `field-run/report.html` shows the same run as the
evidence-boundary page; its Scientific Validity plane is always dark.

## 3. Re-verify the run directory

```sh
python -m science_gate.cli report field-run
```

This re-checks the receipt's content hash, the ledger hash chain and every
figure in `run.json` against the receipt, then re-renders the reports. Edit
any number in `field-run/run.json` and run it again: the status becomes ERROR
(exit 3), because the recorded run no longer matches its receipt.

## 4. Break it on purpose

Work on a copy, so the example stays intact:

```sh
cp -r examples/field-survey my-survey
```

Then try one edit at a time, re-running
`python -m science_gate.cli verify my-survey/manifest.json --output my-run`
after each, and restore the copy afterwards:

| Edit | Expected result |
|---|---|
| Delete the line for `PLOT-SYN-04` from `data/plots.csv` | FAIL: the declared SHA-256 no longer matches (HASH_MISMATCH). |
| Also update the input's `sha256` in the manifest to the new file's digest | FAIL: `snapshot_completeness` finds an accepted row deleted (OMITTED_POPULATION), and the 6-row closure breaks. |
| Remove `reviewer-b`'s verdict from `reviews/verdicts.json` | ABSTAIN (exit 2): PROTOCOL_BROKEN, a required reviewer recorded no verdict. |
| Change `visit-02`'s `utc` to `2026-03-19T11:40:00Z` | FAIL: SOURCE_MISMATCH, local time minus offset no longer equals the recorded UTC. |
| Keep only the header line of `data/plots.csv` (and update its digest) | FAIL: the input is EMPTY, so the six checks that read it have no row to examine and none can pass (each records the justification EMPTY_POPULATION, which abstains with INSUFFICIENT_EVIDENCE rather than counting as partial execution), and the declared 6-row INDEPENDENT closure is broken (expected 6, accounted 0). Without `expected_rows`, the same edit would ABSTAIN. |

To compute a new digest, use `sha256sum my-survey/data/plots.csv` on POSIX
or `Get-FileHash my-survey/data/plots.csv` in PowerShell, and write the hex
digest in lower case.

## 5. Measure the verifier itself

```sh
python -m science_gate.cli mutate examples/field-survey/manifest.json --output field-mutations
```

The untouched copy must verify as PASS (the accepting baseline). The
harness then plants one defect of its own (M00, a flipped ledger head) and
must detect it before anything is counted. Each operator with a target in
this project is then applied to a fresh copy;
operators whose target is absent here (citations, claims, the dependency
graph, a stored summary) are NOT_APPLICABLE and never count as detections.
`field-mutations/mutation-report.md` lists what was detected, every blind
spot (with the stage at which the defect stopped mattering), the
conservation check that every generated mutant landed in exactly one bucket,
and the sensitivity figure as detected/executed.

## 6. Package it

```sh
python -m science_gate.cli package examples/field-survey/manifest.json --output field-package
```

The corpus is SYNTHETIC with default permissions, so the data is copied into
`field-package/evaluation/`, next to `package.json`, the schemas and the
expected results. A CONTROLLED_LOCAL corpus would be packaged with digests and
retrieval instructions only (see `fixtures/packaging/controlled-local`).

## 7. The whole tour

```sh
python -m science_gate.cli demo
```

runs every command against the bundled synthetic fixtures and prints a table
of expected against actual results. It exits 0 only if every expectation
holds.
