# Mutation-testing fixtures

Everything here is **synthetic**. The samples, sites, reviewers, citations,
authors and journals are invented. DOIs use the `10.5555` test prefix. No
file reports a real finding, and no result produced from these files verifies
anything scientific.

## `rich/`

One evidence tree with three manifests. All three verify as PASS, which is
the accepting baseline that mutation testing (ARCHITECTURE.md sections 10
and 17.12) requires.

| manifest | checks | operators with a target |
|---|---|---|
| `manifest-core.json` | the verifier's own kinds: row count, columns, duplicates, snapshot, two numeric agreements, reviewers, time source, summary | 16 (every operator except M08, M09, M13, M18, M19) |
| `manifest.json` | the same, plus `verification_log`, `citation_resolver`, `citation_metadata`, `claim_registry` and `dependency_currency` | all 21 |
| `manifest-blind-spot.json` | `manifest-core.json` without the `reviewer_protocol` check | 16, of which M05 and M06 escape as blind spots: the pinned summary turns those mutants FAIL, but the detector each expects never runs |

`science-gate demo` runs the mutation suite on `manifest-blind-spot.json`,
so its report shows detections and blind spots side by side.

What the tree holds:

- `data/measurements.csv` (CSV, 8 rows) and `data/sites.json` (JSON array,
  4 records): two required inputs, each with a declared digest and an
  INDEPENDENT `expected_rows`.
- `snapshots/accepted.json`: every row of both inputs, as accepted.
- `reviews/verdicts.json`: one verdict from each of the two required
  reviewers.
- `time/events.json`: three observations, at `+02:00`, `UTC` and `-05:30`.
- `claims/registry.json`, `claims/manuscript.md`, `outputs/results.json`,
  `outputs/results-table.md`, `analysis/recipe.md`: two registered claims,
  their stored outputs, and a manuscript whose only numbers are those claims.
- `citations/entries.json`, `citations/frozen.json`,
  `citations/verification-log.json`: two citations, their frozen resolver
  records, and a log with one invocation per claimed verification. The
  frozen set also holds one canary record for the `10.5555` prefix
  (`10.5555/science-gate-canary-0abe942fa8c3`, captured NOT_FOUND with body
  responseCode 100), the negative control that section 17.14 requires before
  any DOI under that prefix may count as resolved.
- `graph/graph.json` and `graph/design/protocol.md`: a dependency graph from
  the sources and a DESIGN node to a FIGURE_OR_TABLE and a CONCLUSION.
- `claims/summary.json`: a stored PASS summary that pins both inputs and
  every other evidence file.

## `activation/`

A three-row synthetic tree for activation receipts and harness
self-mutation (ARCHITECTURE.md 17.12, extensions #11 and #13). Its one
manifest declares `data/samples.csv` (digest declared, INDEPENDENT
`expected_rows` 3) and a dependency graph, but only a `row_count` check:

- `graph/design/protocol.md` is a DESIGN node file that no check opens,
  because no `dependency_currency` check is declared. M18 changes it, so M18
  is a BLIND_SPOT at stage NOT_READ.
- There is no `duplicate_rows` check, so M04's extra row is noticed by
  `row_count` (FAIL) but never by the detector M04 expects: a blind spot
  that a status-only detection rule would wrongly credit (harness mutant H02).
- Twelve operators have no target, which a harness that counts unexecuted
  mutants as executed (H04) cannot hide from the conservation identities.

The tree mutates in about a second, so the harness self-mutation test runs
the honest harness and all seven harness mutants over it.

## Editing

The digests interlock, so a hand edit to any file breaks the baseline. The
digests involved are:

- the manifests' input `sha256`;
- the snapshot's row digests;
- the summary's pins;
- the graph's `recorded_sha256`;
- the registry's stored-output `sha256`;
- the registry's `input_manifest_sha256`, which is the digest of `manifest.json`.

After any change, recompute every digest that covers the changed file. Then
confirm that the manifests still verify as PASS:

```
science-gate verify fixtures/mutations/rich/manifest-core.json --output <dir>
science-gate verify fixtures/mutations/rich/manifest.json --output <dir>
science-gate verify fixtures/mutations/activation/manifest.json --output <dir>
```

`.gitattributes` stops Git from converting line endings, so the files keep
the exact bytes their digests cover.
