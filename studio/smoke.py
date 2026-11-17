#!/usr/bin/env python3
"""End-to-end live Gradio contract smoke: HTML, real CLI API, negative controls.

No browser automation, secret, training or provider write. The URL must be
explicit; by default only a local loopback deployment is contacted.
"""
from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

POSITIVE = "Baseline · witnessed clean result"
NEGATIVE = "Duplicate · mutation re-pinned, checker must reject"


def endpoint(base: str) -> str:
    value = urlsplit(base)
    if (
        value.scheme not in ("http", "https") or not value.netloc
        or value.username or value.password or value.query or value.fragment
        or value.path not in ("", "/")
    ):
        raise ValueError("expected plain HTTP(S) origin without credentials or path")
    # Scope is exact. Permit known public HF Space hosts and loopback only.
    host = (value.hostname or "").lower()
    if not (
        host in ("localhost", "127.0.0.1")
        or host == "szlholdings-szl-science-gate-studio.hf.space"
    ):
        raise ValueError("unapproved product origin")
    if value.scheme == "http" and host not in ("localhost", "127.0.0.1"):
        raise ValueError("public product requires HTTPS")
    return urlunsplit((value.scheme, value.netloc, "", "", "")).rstrip("/")


def get_json(url: str):
    with urlopen(Request(url, headers={"Accept": "application/json"}), timeout=25) as response:
        if response.status != 200:
            raise ValueError("product HTTP response not OK")
        return json.loads(response.read(120_000))


def call(base: str, name: str, data: list) -> list:
    payload = json.dumps({"data": data}, ensure_ascii=False).encode("utf-8")
    req = Request(
        f"{base}/gradio_api/call/{name}", data=payload, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urlopen(req, timeout=25) as response:
        event = json.loads(response.read(2000))
    eid = event.get("event_id")
    if not isinstance(eid, str) or not eid.isalnum() or len(eid) > 64:
        raise ValueError("no bounded Gradio event id")
    with urlopen(f"{base}/gradio_api/call/{name}/{eid}", timeout=60) as response:
        stream = response.read(500_000).decode("utf-8")
    if "event: error" in stream:
        raise ValueError("product execution returned an error")
    for block in stream.split("\n\n"):
        if block.startswith("event: complete"):
            rows = [line[6:] for line in block.splitlines() if line.startswith("data: ")]
            if len(rows) != 1:
                raise ValueError("unexpected API event shape")
            data = json.loads(rows[0])
            if not isinstance(data, list):
                raise ValueError("expected list response")
            return data
    raise ValueError("no terminal complete event")


def smoke(base_url: str) -> dict:
    base = endpoint(base_url)
    config = get_json(base + "/config")
    names = {
        row["api_name"] for row in config.get("dependencies", [])
        if isinstance(row, dict) and isinstance(row.get("api_name"), str)
    }
    if not {"verify_synthetic", "lutar_what_if"} <= names:
        raise ValueError("Gradio UI/API source contract missing")
    good = call(base, "verify_synthetic", [POSITIVE])
    if not (len(good) == 4 and "szl-outcome pass" in good[0]
            and "ACTUAL ENGINE VERDICT" in good[0]
            and "WITNESSED" in good[1]
            and "WHAT WAS EXPECTED" in good[2]):
        raise ValueError("positive run lacks a witnessed real execution/report")
    bad = call(base, "verify_synthetic", [NEGATIVE])
    if not (len(bad) == 4 and "szl-outcome fail" in bad[0]
            and "ACTUAL ENGINE VERDICT" in bad[0]):
        raise ValueError("known-invalid re-hashed fixture did not fail")
    math = call(base, "lutar_what_if", [.8, .7, False, False, False, False, False, False])
    if len(math) != 1 or "SIMULATED_HOLD" not in math[0] or "NOT LIVE ATTESTATION" not in math[0]:
        raise ValueError("Lutar what-if incorrectly elevated to authority")
    return {
        "schema": "szl.science-gate-studio-smoke/v1",
        "origin": base,
        "status": "PASS",
        "config": "OBSERVED",
        "positive": "WITNESSED_PASS",
        "negative": "REJECTED",
        "math": "SIMULATED_HOLD",
        "external_scientific_validation": False,
        "production_release_authority": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:7860")
    args = parser.parse_args()
    try:
        print(json.dumps(smoke(args.base_url), indent=2, sort_keys=True))
    except Exception as exc:
        print("STUDIO_SMOKE_HOLD: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
