"""Publish a source-pinned, synthetic-only HF Gradio Space for SZL Science Gate.

The GitHub protected main SHA is the sole source of the Python application.
A new Space may be created only with --allow-create, and every write requires
--publish. Validation uses exact resulting Space revision and original bytes.
No model/GPU job, lab record, external credential file or dataset is uploaded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

SOURCE = "https://github.com/szl-holdings/scientific-evidence-gate.git"
SPACE = "SZLHOLDINGS/szl-science-gate-studio"
GRADIO_VERSION = "6.20.0"
SOURCE_RE = re.compile(r"[0-9a-f]{40}\Z")


class PublishHold(ValueError):
    pass


def payload(sha: str) -> dict[str, bytes]:
    if type(sha) is not str or SOURCE_RE.fullmatch(sha) is None:
        raise PublishHold("exact lower-case 40-character Git source SHA required")
    readme = f"""---
title: SZL Science Gate Studio
emoji: 🔬
colorFrom: blue
colorTo: green
sdk: gradio
sdk_version: {GRADIO_VERSION}
app_file: app.py
python_version: 3.12
suggested_hardware: cpu-basic
license: other
short_description: Interactive synthetic evidence verifier
---

# SZL Science Gate Studio

**REAL CODE / SYNTHETIC DATA / NO BIOLOGICAL OR PRODUCTION VALIDATION.**

Interactive interface for the source-locked SZL scientific-evidence-gate. Each
click runs the canonical Python CLI on independently copied, sealed synthetic
fixtures: pass, digest drift, duplicate, empty population, inconsistent mean,
and narrated citation. Outputs include check verdicts, mutation witnesses,
execution ledgers, report, and synthetic reproducibility ZIP.

**Exact application source:** [{sha}](https://github.com/szl-holdings/scientific-evidence-gate/tree/{sha})
(only mutable metadata is this Space's own Git revision, verified by publisher).

No patient or unpublished laboratory records. No model training, GPU, passwords,
private data, internal endpoints, dynamic user code, or cloud access credentials.
Lutar arithmetic panel is a visitor-controlled WHAT-IF simulation, not an
authenticated release gate. The repo's LICENSE contains Apache-2.0 text while
its package metadata declares NOASSERTION; metadata reconciliation remains
an upstream owner responsibility, so the Space card does not assert a
resolved license identifier.

This public demonstration is separate from any partner-laboratory protocol
freeze or signature and does not imply independent B1 reproduction.

[GitHub protected source](https://github.com/szl-holdings/scientific-evidence-gate)
· [SZL Holdings](https://github.com/szl-holdings)
"""
    description_lines = [line.split(":", 1)[1].strip() for line in readme.splitlines()
                         if line.startswith("short_description:")]
    if len(description_lines) != 1 or not 1 <= len(description_lines[0]) <= 60:
        raise PublishHold("invalid Hub Space card short_description")
    requirements = (
        f"gradio=={GRADIO_VERSION}\n"
        "scientific-evidence-gate @ git+"
        f"{SOURCE}@{sha}\n"
    )
    app = f"""# Compiled from GitHub immutable source; no code copied into this HF repo.
import os

os.environ["SZL_STUDIO_SOURCE_SHA"] = "{sha}"
os.environ.setdefault("PORT", "7860")
from science_gate.studio import main

if __name__ == "__main__":
    main()
"""
    provenance = {
        "schema": "szl.science-gate-hf-source/v1",
        "source": "szl-holdings/scientific-evidence-gate",
        "source_commit": sha,
        "space": SPACE,
        "sdk": "gradio",
        "sdk_version": GRADIO_VERSION,
        "source_install": "exact_git_commit",
        "data": "SYNTHETIC_ONLY",
        "source_binding": "PINNED_INSTALL_NOT_A_SIGNED_ATTESTATION",
        "biological_validation": False,
        "clinical_validation": False,
        "training_authority": "NONE",
        "publisher_signature": "NOT_PROVIDED",
    }
    files = {
        "README.md": readme.encode("utf-8"),
        "requirements.txt": requirements.encode("utf-8"),
        "app.py": app.encode("utf-8"),
        "SOURCE.json": (json.dumps(provenance, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    }
    return files


def verify_protected_main(sha: str) -> None:
    if type(sha) is not str or SOURCE_RE.fullmatch(sha) is None:
        raise PublishHold("source SHA invalid")
    try:
        result = subprocess.run(
            ["git", "ls-remote", SOURCE, "refs/heads/main"],
            capture_output=True, text=True, timeout=30, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PublishHold("unable to observe GitHub protected main") from exc
    fields = result.stdout.strip().split()
    if len(fields) != 2 or fields[0] != sha or fields[1] != "refs/heads/main":
        raise PublishHold("source SHA does not equal current protected main")


def publish(sha: str, *, allow_create: bool = False) -> dict:
    from huggingface_hub import HfApi, hf_hub_download
    from huggingface_hub.errors import RepositoryNotFoundError

    verify_protected_main(sha)
    api = HfApi()
    who = api.whoami()
    orgs = who.get("orgs", ())
    authorized_org = any(
        (o.get("name") if isinstance(o, dict) else o) == "SZLHOLDINGS"
        for o in orgs
    )
    if not authorized_org:
        raise PublishHold("connected Hub account is not SZLHOLDINGS member")
    files = payload(sha)
    created = False
    try:
        existing = api.space_info(SPACE)
    except RepositoryNotFoundError:
        existing = None
    if existing is None:
        if not allow_create:
            raise PublishHold("Space does not exist; --allow-create required")
        api.create_repo(
            SPACE, repo_type="space", space_sdk="gradio",
            private=False, exist_ok=False,
        )
        created = True
    else:
        if existing.sdk != "gradio" or existing.private is True:
            raise PublishHold("existing Space has unexpected SDK or visibility")
    verify_protected_main(sha)  # avoid deploying after main advances
    with tempfile.TemporaryDirectory(prefix="szl-science-gate-hf-") as temp:
        root = Path(temp)
        for name, raw in files.items():
            (root / name).write_bytes(raw)
        api.upload_folder(
            folder_path=str(root), repo_id=SPACE, repo_type="space",
            commit_message=f"Deploy exact science-gate source {sha[:12]} (synthetic only)",
            allow_patterns=sorted(files),
        )
        remote = api.space_info(SPACE)
        remote_sha = remote.sha
        if not remote_sha or not SOURCE_RE.fullmatch(remote_sha):
            raise PublishHold("Hub revision not immutable")
        for name, expected in files.items():
            actual = Path(
                hf_hub_download(repo_id=SPACE, repo_type="space",
                                filename=name, revision=remote_sha)
            ).read_bytes()
            if actual != expected:
                raise PublishHold(f"Hub immutable byte readback mismatch: {name}")
    verify_protected_main(sha)
    return {
        "schema": "szl.science-gate-publication-result/v1",
        "space": SPACE, "source_git_sha": sha, "hub_sha": remote_sha,
        "new_space_created": created,
        "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()},
        "immutable_byte_readback": "PASS",
        "runtime_status": "NOT_VERIFIED_BY_PUBLISHER",
        "training_started": False, "model_published": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--allow-create", action="store_true")
    args = parser.parse_args()
    try:
        files = payload(args.source_sha)
        if not args.publish:
            print(json.dumps({
                "status": "DRY_RUN_NO_PROVIDER_MUTATION",
                "space": SPACE, "source": args.source_sha,
                "files": {name: hashlib.sha256(raw).hexdigest()
                          for name, raw in files.items()},
            }, indent=2, sort_keys=True))
            return 0
        print(json.dumps(publish(args.source_sha, allow_create=args.allow_create),
                         indent=2, sort_keys=True))
        return 0
    except PublishHold as exc:
        print("HOLD: " + str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
