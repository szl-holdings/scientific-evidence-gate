# Contributing

Thank you for helping. The bar for a change is the project's governing rule:
a passing check must emit enough evidence to prove that it had the
opportunity to fail. A change that makes a PASS easier to reach without new
evidence will not be accepted.

## Ground rules

- **Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first.** It is the
  binding contract: names, enums, file names, field names and exit codes.
  If a change needs the contract to change, change the contract in the same
  pull request and say why.
- **Standard library only at runtime.** Python 3.11 or later. No runtime
  dependencies, no `shell=True`, and no process built from manifest or input
  text. The package itself never starts a subprocess; only the test suite
  runs the CLI as one.
- **Every write goes through `science_gate._safeio.safe_write`.**
- **Missing evidence is never zero, false, PASS or "no defects".** An unknown
  count is `None` (JSON `null`) with an explicit state.
- **Determinism.** Sort mappings and sets before output. Take time only from
  `science_gate._clock.now()`. Derive identifiers from content hashes, never
  from random numbers (`uuid4` is forbidden). Floats never enter hashed
  content.
- **No claims of scientific verification**, in code, reports, fixtures or
  documentation.

## Fixtures and test data

Fixtures are synthetic. Use obviously invented names (`SYN-0001`,
`reviewer-a`, `site-alpha`), DOIs under the `10.5555` test prefix, and data
you generate. Never add real people, institutions, citations, credentials or
controlled data. Fixture trees carry a `.gitattributes` with `* -text`,
because their recorded digests cover exact bytes, including line endings.
Several fixtures have interlocking digests (snapshots, summaries, graphs,
registries); `fixtures/mutations/README.md` lists what to recompute after an
edit.

## Running the tests

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests
```

- `tests/test_required.py` holds one test per numbered requirement,
  `test_r01_...` to `test_r28_...`. Keep the mapping one to one.
- `tests/test_security.py` covers ARCHITECTURE.md section 15, and
  `tests/test_determinism.py` covers section 16 (two CLI runs with different
  `PYTHONHASHSEED` values and a fixed clock, compared byte for byte).
- Tests write only into OS temporary directories and remove them. They never
  touch the network; network paths are exercised through injected openers.
- Symlink tests skip with a visible reason where the account cannot create
  symbolic links. A skip must never be turned into a pass.

Then run the self-checking demonstration:

```sh
PYTHONPATH=src python -m science_gate.cli demo
```

It must exit 0.

## Style

Clear, idiomatic code with type hints. Docstrings explain why, not only
what. No dead code. Keep lines readable (the existing code stays within about
120 characters).

## Licensing

No license has been chosen for this project (NOASSERTION). Do not add a
license file, license headers or an authors list in a contribution; that
decision belongs to the repository owner.
