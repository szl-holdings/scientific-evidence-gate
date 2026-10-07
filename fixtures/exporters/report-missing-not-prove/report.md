## STATUS

**FAIL** (SOURCE_MISMATCH), exit code 1.

- Run: `run-d36af7aab43267d5`
- Started 2026-01-02T03:04:05Z; completed 2026-01-02T03:04:05Z
- Reasons: SOURCE_MISMATCH, PROTOCOL_BROKEN
- Failure modes: PROTOCOL_DRIFT, SOURCE_MISMATCH
- Verdict rises: NONE -> PASS at step 1 (`check:rows`, VERIFIED); PASS -> FAIL at step 2 (`check:duplicates`, SOURCE_MISMATCH)
- Evidence manifest sha256: `89bd93aceb78a780b266e2a194fbd7b60c22ad8e6a56b33c4f20190bf4bdfc80`
- Ledger: 15 entries, head `00ef384093b54cba15925493f7a0dbd992967e29022bdb56e6a737be5520e4c0`
- Receipt: content sha256 `c36b901c28c7fe33ab9344abd33d41d4d78d1f592787520ba22cbae89a1e0dc1`, UNSIGNED
- Scope: integrity and the declared evaluation only. Scientific validity is not established by this tool.

## WHAT WAS EXPECTED

- Manifest `manifest.json`, sha256 `9557dcef32f1c7a8bd3e824f92d1d69e67cbade32fdac4d7ffa94250eaac1d77`, run label `synthetic-exporter`

Inputs declared: 1 (expected_inputs 1)

- `measurements`: `data/measurements.csv`, csv, required, expected_rows 6 (INDEPENDENT), declared sha256 `869837d836c85516e870924b62b12403af3972e2a6bf529e888ab8fd4648b185`

Checks declared: 3, of which 3 required (checks_expected 3)

- `duplicates`: duplicate_rows v1, required, inputs measurements
- `reviews`: reviewer_protocol v1, required, inputs 
- `rows`: row_count v1, required, inputs measurements

PASS requires: every required input found, opened, parsed and matching any declared digest; at least one input opened; at least one data row examined; checks_executed == checks_expected; every required check PASS with a falsifier witness showing it could have failed; every applicable invariant holding; a non-empty evidence manifest.

## WHAT WAS EXAMINED

- Input funnel: expected 1 -> discovered 1 -> opened 1 -> parsed 1 -> examined 1; input closure holds (1 of 1, INDEPENDENT)
- rows_examined: 6 (distinct data rows of declared inputs read by an executed check)
- Each check line under WHAT PASSED, WHAT FAILED and WHAT ABSTAINED gives that check's own subject records examined (its run.json checks[].rows_examined); those figures are not summed.

Inputs:

- `measurements` PARSED: `data/measurements.csv`, sha256 `869837d836c85516e870924b62b12403af3972e2a6bf529e888ab8fd4648b185`, 212 bytes, 6 records (admitted 6, excluded 0, deferred 0, unresolved 0, failed 0); row closure holds (6 of 6, INDEPENDENT)

Other documents read:

- none

## WHAT ACTUALLY RAN

- checks_executed 3 of checks_expected 3 (required checks that reached CHECKED with a terminal invocation)
- Ledger sealed at 15 entries, head `00ef384093b54cba15925493f7a0dbd992967e29022bdb56e6a737be5520e4c0`
- PLAN: ledger entry 1, entry sha256 `63049643cc3163544262a2aea9a05f5d23b0c1fdd5a8c34ce5d38f924e08c905`, written before any check ran: 1 input(s), 3 check(s) and 4 pin(s) planned, manifest sha256 `9557dcef32f1c7a8bd3e824f92d1d69e67cbade32fdac4d7ffa94250eaac1d77`

Invocations:

- `duplicates` (duplicate_rows v1): invocation `inv-4b956d10114c`, CHECKED, FAIL; no falsifier ran (only a would-be PASS is falsified)
- `reviews` (reviewer_protocol v1): invocation `inv-10b4eea1e171`, CHECKED, ABSTAIN; no falsifier ran (only a would-be PASS is falsified)
- `rows` (row_count v1): invocation `inv-325393fa8605`, CHECKED, PASS; falsifier witness WITNESSED (1 of 1 case(s) rejected as expected)

Controls (each its own invocation, never counted as a check):

- comparator self-test: invocation `inv-a171155a9a3c`, 3 of 3 known pair(s) compared as expected; holds
- canary: must_fail invocation `inv-a081c642d5cb` gave FAIL (SOURCE_MISMATCH), expected FAIL; must_pass invocation `inv-2e2cd435607b` gave PASS (VERIFIED), expected PASS; holds
- harness pins: 4 file(s) pinned; changed: none; writes to pinned paths: none; holds
- falsifier witnesses: WITNESSED 1 (`rows`), REFUTED 0, UNWITNESSED 0, NO_CASE 0, NO_GENERATOR 0; 1 falsifier invocation(s)
- claim-to-invocation join: no claim_join check ran

## WHAT PASSED

Checks:

- `rows`: row_count PASS (VERIFIED), subject records examined 6

Weakest discrimination: no PASS result records a discrimination ratio

Invariants that hold:

- none

## WHAT FAILED

Findings:

- none

Checks:

- `duplicates`: duplicate_rows FAIL (SOURCE_MISMATCH), subject records examined 6; row_key SYN-0003 appears twice

## WHAT ABSTAINED

Findings:

- none

Checks:

- `reviews`: reviewer_protocol ABSTAIN (PROTOCOL_BROKEN), subject records examined 1; required reviewer reviewer-b gave no verdict

## WHAT REMAINS UNRESOLVED

- the receipt is UNSIGNED (receipt.auth.json says so): its content hash detects accidental change, but anyone able to edit the run directory can rewrite and rehash it

## FILES

- `run.json`
- `report.md`
- `results.sarif`
