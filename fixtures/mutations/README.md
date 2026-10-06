# Mutation-testing fixtures

Everything here is **synthetic**. The samples, sites, reviewers, citations,
authors and journals are invented. DOIs use the `10.5555` test prefix. No
file reports a real finding, and no result produced from these files verifies
anything scientific.

## `rich/`

One evidence tree with three manifests. All three verify as PASS, which is
the accepting baseline that mutation testing (ARCHITECTURE.md section 10)
requires.

| manifest | checks | operators with a target |
|---|---|---|
| `manifest-core.json` | the verifier's own kinds: row count, columns, duplicates, snapshot, two numeric agreements, reviewers, time source, summary | 15 (every operator except M08, M09, M13, M18, M19) |
| `manifest.json` | the same, plus `verification_log`, `citation_resolver`, `citation_metadata`, `claim_registry` and `dependency_currency` | all 20 |
| `manifest-blind-spot.json` | `manifest-core.json` without the `reviewer_protocol` check | 15, of which M05 and M06 escape as blind spots: the pinned summary turns those mutants FAIL, but the detector each expects never runs |

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
  records, and a log with one invocation per claimed verification.
- `graph/graph.json` and `graph/design/protocol.md`: a dependency graph from
  the sources and a DESIGN node to a FIGURE_OR_TABLE and a CONCLUSION.
- `claims/summary.json`: a stored PASS summary that pins both inputs and
  every other evidence file.

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
confirm that both manifests still verify as PASS:

```
science-gate verify fixtures/mutations/rich/manifest-core.json --output <dir>
science-gate verify fixtures/mutations/rich/manifest.json --output <dir>
```

`.gitattributes` stops Git from converting line endings, so the files keep
the exact bytes their digests cover.
