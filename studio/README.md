# SZL Science Gate Studio — live interactive product

**Product:** interactive evidence verification with the actual
`science_gate.cli verify` engine. **Target:** a CPU-only public Hugging Face
Space, `SZLHOLDINGS/szl-science-gate-studio`. This source repository is the
single authority. No copies of the Python verifier are maintained in the
Space: a pinned Git SHA is installed at container build time.

## Capabilities

- One-click verification on six **bundled synthetic** experiments: a clean
  passing fixture, digest tampering, a re-hashed duplicate that still fails
  independent validation, an empty population, an inconsistent numeric mean,
  and a narrated citation that does not amount to verification.
- Every click runs the canonical source verifier in a bounded fresh temporary
  directory with **network lookups disabled**. The UI only renders returned
  `run.json` and `report.md`; it never manufactures verdicts.
- Downloadable ZIP of the **exact synthetic input, manifest, execution ledger,
  falsifier controls, receipt statement, authentication sidecar, SARIF and
  machine report**, plus source-identifying metadata. The UI never accepts
  arbitrary URLs, file paths, executable code or a user-provided upload.
- A visitor-controlled Lutar arithmetic **WHAT-IF** lab. The equal-weight
  geometric mean and gating are numerical demonstrations, **not** a Lean
  refinement proof, a cryptographic signature or runtime release admission.
- Programmatic Gradio endpoints: `verify_synthetic` and `lutar_what_if`.

## Trust boundary

The Space is a <b>public synthetic demonstration</b>, not a biological
validation service. The viewer must never upload patient, unpublished
wet-lab, confidential, proprietary or controlled data. Its source fixture
package contains invented sample IDs only. No Model or GPU weights,
financial secrets, database connection, third-party web access, or
autonomous publishing side effects exist in the runtime.

The ZIP includes a normal evidence-chain receipt. If it is unsigned, it
remains **unsigned**. A hash-chain with the first head retained only by the
author is not an independent timestamp. A PASS means the declared synthetic
rules rejected their known-bad controls, not that the submitted scientific
conclusion is objectively correct.

**License status:** `LICENSE` in the canonical repository contains
Apache-2.0 text, whereas `pyproject.toml` declares `NOASSERTION`.
The Space card uses `license: other` until that upstream inconsistency is
resolved through ordinary owner review. It is not a representation of a
signed or frozen partner protocol.

## Local full-stack run

```sh
# from this GitHub repository checkout
export PYTHONPATH=src
python -m unittest discover -s tests -p 'test_studio*.py' -v
python -m science_gate.studio
# browse http://127.0.0.1:7860 (runs on 0.0.0.0 for container access)
```

The UI depends on `gradio==6.20.0` as an optional deployment layer; the
science-gate engine and all verification tests use only Python stdlib.
To smoke-test a local Gradio server, query `GET /config` and invoke its
named `verify_synthetic` function. Gradio's health response alone is not
proof of a verified result: execute a negative case and inspect its result.

## One-way governed publication

After source PR is fully green and merged to protected main, obtain the
new exact main SHA and preview the four-file HF Space payload:

```sh
python studio/deploy_hf.py --source-sha EXACT_PROTECTED_MAIN_SHA
```

Only the following explicit command may write to the HF org:

```sh
python studio/deploy_hf.py --source-sha EXACT_PROTECTED_MAIN_SHA \
  --publish --allow-create
```

The publisher requires the source SHA to equal the observed GitHub main
at start, immediately before upload and after the response; it writes the
Space as an ordinary `gradio` repository on CPU Basic, then checks every
uploaded file's **exact original bytes** at the newly observed Hub commit.
A successful write still reports runtime status **NOT_VERIFIED_BY_PUBLISHER**.
Check the actual Space build status, HTTP root, frontend configuration, named
backend route invocation, and app logs independently before claiming LIVE.
Changing main later requires a new, explicit source-pinned publication.

## Integration roadmap

A future restricted installation can expose lab-owned fixtures and gate
validation inside the lab's own authentication and storage boundary,
reusing this same canonical engine. Such an installation must separately
implement real auth, durable signed receipts, complete fixture licensing,
operator independence, audit retention, rate limits, isolation and
publication qualification. Those controls are not supplied by the public
synthetic demonstrator. Do not claim that the Vidal-Gadea Lab has deployed or
endorsed this product.
