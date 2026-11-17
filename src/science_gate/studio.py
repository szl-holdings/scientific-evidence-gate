"""Public synthetic Science Gate Studio: real verifier, no real lab data.

Thin, non-authoritative presentation over the canonical science_gate CLI.
No new release controller, persistent evidence store, model training, or
claims about biological validity. Only bounded, bundled synthetic fixtures
are accepted; no arbitrary file uploads, dynamic manifest, URLs, or code.
"""
from __future__ import annotations

import contextlib
import html
import hashlib
import io
import json
import math
import os
from pathlib import Path
import shutil
import tempfile
import threading
import time
import uuid
import zipfile
from typing import Any

from . import __version__, cli
from ._resources import bundled_dir

SCENARIOS = {
    "Baseline · witnessed clean result": ("core/valid", None),
    "Tamper · original digest no longer matches": ("core/valid", "tamper"),
    "Duplicate · mutation re-pinned, checker must reject": ("core/valid", "duplicate"),
    "Empty population · coverage unavailable": ("core/empty", None),
    "Inconsistent mean · numeric claim cannot hold": ("numeric/grim-inconsistent", None),
    "Narrated citation · no observed verification": ("citations/narrated-log", None),
}
SCHEMA = "szl.science-gate-studio-result/v1"
SOURCE_MATH = "szl-holdings/lutar-lean@c2ca813fca00ecf58bcc5f505f2aa4237fbf2481"
SOURCE_CODE = "https://github.com/szl-holdings/scientific-evidence-gate"
MAX_FIXTURE_BYTES = 256_000
MAX_ARCHIVE_BYTES = 2_000_000
_ENGINE_LOCK = threading.Lock()
CLAIM_BOUNDARY = (
    "Synthetic, locally executed verifier demonstration. A PASS proves only "
    "the declared synthetic checks with the displayed falsifier evidence. "
    "It does not establish scientific truth, independent reproduction, "
    "laboratory validity, model training, or production admission."
)


class StudioHold(ValueError):
    """A controlled refusal; never turn a missing result into PASS."""


def _source_dir(relative: str) -> Path:
    base = bundled_dir("fixtures")
    if base is None:
        raise StudioHold("bundled synthetic fixtures unavailable")
    source = base.joinpath(*relative.split("/"))
    if not source.is_dir():
        raise StudioHold("selected fixture unavailable")
    return source


def _mutate(project: Path, mode: str | None) -> None:
    if mode not in (None, "tamper", "duplicate"):
        raise StudioHold("unexpected mutation")
    if mode is None:
        return
    path = project / "data" / "measurements.csv"
    raw = path.read_bytes()
    if len(raw) > MAX_FIXTURE_BYTES:
        raise StudioHold("fixture exceeds bound")
    lines = raw.decode("utf-8").splitlines()
    if len(lines) != 7 or "SYN-0001" not in lines[1]:
        raise StudioHold("canonical fixture layout changed; refuse drift")
    if mode == "tamper":
        edited = raw.replace(b"12.40", b"12.41", 1)
        if edited == raw:
            raise StudioHold("tamper could not be applied")
        # Intentionally leave the *original* manifest digest: source mismatch.
        path.write_bytes(edited)
        return
    lines[-1] = lines[1]  # six records, but two share the same sample_id
    edited = ("\n".join(lines) + "\n").encode("utf-8")
    path.write_bytes(edited)
    manifest_path = project / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    if not isinstance(manifest.get("inputs"), list) or len(manifest["inputs"]) != 1:
        raise StudioHold("manifest identity changed")
    # The intentionally bad row is honestly bound to its new SHA, demonstrating
    # that hashing source bytes alone is not a sufficient scientific check.
    manifest["inputs"][0]["sha256"] = hashlib.sha256(edited).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _receipt_archive(project: Path, result_dir: Path, scenario: str, metadata: dict) -> str:
    root = Path(tempfile.gettempdir()) / "szl-science-gate-synthetic-downloads"
    root.mkdir(parents=True, exist_ok=True)
    now = time.time()
    # Bound retained synthetic outputs to avoid uncontrolled disk growth.
    existing = sorted(root.glob("synthetic-*.zip"), key=lambda f: f.stat().st_mtime)
    for old in existing:
        try:
            if now - old.stat().st_mtime > 3600:
                old.unlink()
        except OSError:
            pass
    remaining = sorted(root.glob("synthetic-*.zip"), key=lambda f: f.stat().st_mtime)
    for old in remaining[:-31]:
        try:
            old.unlink()
        except OSError:
            pass
    target = root / f"synthetic-{uuid.uuid4().hex}.zip"
    n_bytes = 0
    with zipfile.ZipFile(target, "x", zipfile.ZIP_DEFLATED) as archive:
        for base, prefix in ((project, "fixture"), (result_dir, "run")):
            for path in sorted(base.rglob("*")):
                if path.is_symlink():
                    raise StudioHold("fixture contains a symlink")
                if path.is_dir():
                    continue
                if not path.is_file():
                    raise StudioHold("fixture contains a non-regular file")
                raw = path.read_bytes()
                n_bytes += len(raw)
                if n_bytes > MAX_ARCHIVE_BYTES:
                    raise StudioHold("synthetic bundle exceeds export cap")
                arcname = prefix + "/" + path.relative_to(base).as_posix()
                archive.writestr(arcname, raw)
        archive.writestr(
            "STUDIO_SOURCE.json",
            json.dumps(metadata, sort_keys=True, indent=2) + "\n"
        )
    return str(target)


def verify_scenario(name: str, *, export: bool = False) -> dict[str, Any]:
    """Run the actual science-gate engine over one hardcoded synthetic fixture.

    The app does not accept uploads, arbitrary manifests, paths or dynamic
    checker plugins. This method never alters the canonical fixture package.
    """
    if type(name) is not str or name not in SCENARIOS:
        raise StudioHold("scenario not in the sealed demonstration registry")
    relative, mutation = SCENARIOS[name]
    with tempfile.TemporaryDirectory(prefix="szl-science-gate-studio-") as parent:
        work = Path(parent)
        project = work / "fixture"
        shutil.copytree(_source_dir(relative), project, symlinks=False)
        _mutate(project, mutation)
        result_dir = work / "run"
        # The canonical source contract prohibits starting a process from
        # the science_gate package. Drive its CLI IN PROCESS, serialized so
        # its global stdout/redaction context never overlaps another run.
        buffer = io.StringIO()
        started = time.monotonic()
        with _ENGINE_LOCK:
            with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
                code = cli.main(["verify", str(project / "manifest.json"),
                                 "--output", str(result_dir)])
        if time.monotonic() - started > 20:
            raise StudioHold("synthetic verifier exceeded the demonstration budget")
        result_path = result_dir / "run.json"
        if not result_path.is_file():
            raise StudioHold(f"verifier produced no complete receipt (exit {code})")
        result = json.loads(result_path.read_text(encoding="utf-8"))
        status = result.get("status")
        codes = {"PASS": 0, "FAIL": 1, "ABSTAIN": 2, "ERROR": 3}
        if status not in codes or code != codes[status]:
            raise StudioHold("verifier exit code and receipt disagree")
        checks = result.get("checks")
        if not isinstance(checks, list):
            raise StudioHold("verifier did not provide a check ledger")
        rows = []
        for check in checks:
            if not isinstance(check, dict):
                raise StudioHold("malformed check result")
            ev = check.get("evidence", {})
            falsifiers = ev.get("falsifiers", []) if isinstance(ev, dict) else []
            rows.append({
                "id": check.get("check_id"),
                "kind": check.get("kind"),
                "verdict": check.get("verdict"),
                "reason": check.get("reason"),
                "examined": check.get("rows_examined"),
                "falsifier": ev.get("falsification", "UNAVAILABLE") if isinstance(ev, dict)
                else "UNAVAILABLE",
                "negative_controls": len(falsifiers) if isinstance(falsifiers, list) else 0,
            })
        meta = {
            "schema": SCHEMA,
            "scenario": name,
            "synthetic": True,
            "tool_version": __version__,
            "studio_source_sha": os.getenv("SZL_STUDIO_SOURCE_SHA", "UNBOUND_LOCAL"),
            "source_repository": SOURCE_CODE,
            "method": "canonical science_gate.cli.main in-process; network lookups disabled",
            "biological_validation": False,
            "independent_lab_reproduction": False,
            "release_admission": False,
            "signing_claim": "NONE",
        }
        output = {
            **meta,
            "status": status, "reason": result.get("reason"),
            "run_id": result.get("run_id"),
            "rows_examined": result.get("rows_examined"),
            "expected_inputs": result.get("expected_inputs"),
            "checks_executed": result.get("checks_executed"),
            "checks_expected": result.get("checks_expected"),
            "checks_passed": result.get("checks_passed"),
            "checks_failed": result.get("checks_failed"),
            "checks_abstained": result.get("checks_abstained"),
            "ledger_head_sha256": result.get("ledger_head_sha256"),
            "checks": rows, "boundary": CLAIM_BOUNDARY,
            "original_report": (result_dir / "report.md").read_text(encoding="utf-8")
            if (result_dir / "report.md").is_file() else "REPORT_UNAVAILABLE",
            "archive": None,
        }
        if export:
            output["archive"] = _receipt_archive(project, result_dir, name, meta)
        return output


def simulate_lutar(
    x: float, y: float, required_ci: bool, source_parity: bool,
    signed_receipt: bool, fresh_evidence: bool, live_runtime: bool,
    owner_approved: bool
) -> dict[str, Any]:
    """WHAT-IF math, not authenticated production evidence or a Lean proof."""
    if any(type(z) not in (float, int) or isinstance(z, bool)
           or not math.isfinite(z) or not 0 <= z <= 1 for z in (x, y)):
        raise StudioHold("axes must be finite real numbers in [0,1]")
    for flag in (required_ci, source_parity, signed_receipt, fresh_evidence,
                 live_runtime, owner_approved):
        if type(flag) is not bool:
            raise StudioHold("gate observation must be an explicit boolean")
    score = math.sqrt(x * y)
    missing = [
        k for k, v in (
            ("REQUIRED_CI", required_ci), ("SOURCE_PARITY", source_parity),
            ("SIGNATURE", signed_receipt), ("FRESHNESS", fresh_evidence),
            ("RUNTIME", live_runtime), ("OWNER_APPROVAL", owner_approved),
        ) if not v
    ]
    return {
        "schema": "szl.lutar-what-if/v1",
        "axioms_source": SOURCE_MATH,
        "axes": [x, y],
        "lambda_2": score,
        "maximum": max(x, y),
        "permutation_delta": abs(score - math.sqrt(y*x)),
        "admission_simulation": "ALL_INPUT_FLAGS_TRUE" if not missing else "SIMULATED_HOLD",
        "missing": missing,
        "effective_score": score if not missing else 0.0,
        "authority": "WHAT_IF_ONLY_NO_PRODUCTION_PERMISSION",
        "lean_refinement_proved": False,
    }


def _esc(v: object) -> str:
    return html.escape(str(v), quote=True)


def _dashboard(result: dict) -> str:
    label = _esc(result["status"])
    status = result["status"].lower()
    return (
        f'<section class="szl-outcome {status}">'
        f'<div class="szl-outcome-main"><div class="szl-status-label">ACTUAL ENGINE VERDICT</div>'
        f'<div class="szl-status-value">{label}</div>'
        f'<div class="szl-reason">{_esc(result["reason"])}</div></div>'
        '<div class="szl-metrics">'
        f'<div><strong>{_esc(result["rows_examined"])}</strong><span>rows examined</span></div>'
        f'<div><strong>{_esc(result["checks_executed"])}/{_esc(result["checks_expected"])}</strong><span>checks executed</span></div>'
        f'<div><strong>{_esc(result["checks_passed"])}</strong><span>checks passed</span></div>'
        f'<div><strong>{_esc(result["checks_failed"])}</strong><span>checks failed</span></div>'
        '</div>'
        f'<p class="szl-caveat">Run {_esc(result["run_id"])} · synthetic only · '
        'not independently signed or scientifically validated</p></section>'
    )


def _trace(result: dict) -> str:
    tr = []
    for c in result["checks"]:
        st = _esc(c["verdict"])
        tr.append(
            '<tr><td><strong>'+_esc(c["id"])+'</strong><small>'+_esc(c["kind"])+'</small></td>'
            f'<td><span class="szl-pill">{st}</span></td>'
            f'<td>{_esc(c["examined"])}</td><td>{_esc(c["falsifier"])}</td>'
            f'<td>{_esc(c["negative_controls"])}</td></tr>'
        )
    return (
        '<div class="szl-table-box"><div class="szl-section-label">CHECK EXECUTION LEDGER</div>'
        '<table class="szl-table"><thead><tr>'
        '<th>Check</th><th>Verdict</th><th>Rows</th><th>Falsification</th>'
        '<th>Controls</th></tr></thead><tbody>'
        + "".join(tr) + "</tbody></table></div>"
    )


def _render_case(selection: str):
    try:
        result = verify_scenario(selection, export=True)
        return _dashboard(result), _trace(result), result["original_report"], result["archive"]
    except StudioHold as exc:
        return (
            '<div class="szl-outcome error"><h3>ERROR — controlled refusal</h3>'
            f'<p>{_esc(str(exc))}</p></div>',
            "<p>No trustworthy check receipt was produced.</p>",
            "ERROR: verifier evidence unavailable; this is not a PASS.", None,
        )


def _render_lutar(x, y, a, b, c, d, e, f):
    try:
        r = simulate_lutar(x, y, a, b, c, d, e, f)
    except StudioHold as exc:
        return f'<div class="szl-outcome error">ERROR: {_esc(str(exc))}</div>'
    return (
        '<div class="szl-math-result">'
        '<div class="szl-section-label">SYNTHETIC WHAT-IF / NOT LIVE ATTESTATION</div>'
        f'<div class="szl-math-number">{r["effective_score"]:.4f}</div>'
        '<p>Effective simulated trust · Canonical Lambda<sub>2</sub> '
        f'= {r["lambda_2"]:.4f} · Max bound {r["maximum"]:.4f}</p>'
        f'<div class="szl-status-label">STATE: {_esc(r["admission_simulation"])}</div>'
        f'<p>Missing simulated gates: {_esc(", ".join(r["missing"]) or "none")}</p>'
        '<p class="szl-caveat">Flags are typed by a visitor, not authenticated by GitHub, '
        'Hugging Face, an operator or a signature. A green simulation is NOT production readiness.</p>'
        '</div>'
    )


STYLE = """
:root { --szl-bg:#0a111b; --szl-mist:#e6edf9; --szl-blue:#47b3e8; --szl-green:#64dec3; }
.gradio-container{max-width:1180px!important;margin:auto!important;font-family:Inter,ui-sans-serif,system-ui,sans-serif!important}
body,.gradio-container{background:radial-gradient(circle at 76% 9%,#193653,#0b1625 34%,#07111c 80%)!important;color:#eaf2fc!important}
.szl-hero {padding:37px 40px;margin:15px 0 22px; border:1px solid rgba(130,195,237,.23);border-radius:23px;
background:linear-gradient(118deg,rgba(15,43,65,.92),rgba(9,25,41,.8)); position:relative; overflow:hidden;}
.szl-hero:after{content:"";position:absolute;right:-75px;top:-125px;width:390px;height:390px;border-radius:50%;
border:1px solid rgba(86,222,196,.23);box-shadow:0 0 0 50px rgba(68,133,212,.025),0 0 0 108px rgba(68,133,212,.035);
animation:orbit 13s linear infinite;pointer-events:none}
@keyframes orbit{from{transform:rotate(0)}to{transform:rotate(360deg)}}
.szl-kicker{font-weight:800;color:#61d6b8;letter-spacing:3px;font-size:11px}
.szl-hero h1{color:#f3faff;font-weight:850;font-size:clamp(34px,5vw,58px);letter-spacing:-2px;line-height:1.06;margin:10px 0 16px}
.szl-hero p{font-size:16px;max-width:670px;line-height:1.6;color:#a7bfd8}
.szl-badges{display:flex;gap:9px;flex-wrap:wrap;margin-top:19px}
.szl-badges span{background:rgba(47,101,130,.25);border:1px solid #306080;border-radius:999px;padding:8px 12px;color:#9edccf;font-size:11px;letter-spacing:.4px}
.szl-outcome,.szl-math-result,.szl-table-box{padding:24px;border:1px solid rgba(111,161,198,.26);border-radius:20px;background:linear-gradient(140deg,rgba(16,39,57,.95),rgba(10,25,40,.94));margin:9px 0}
.szl-outcome.pass{border-left:5px solid #5de3b3}.szl-outcome.fail{border-left:5px solid #ef7979}
.szl-outcome.abstain{border-left:5px solid #e7bc69}.szl-outcome.error{border-left:5px solid #cd7be9}
.szl-outcome-main{display:flex;gap:20px;justify-content:space-between;align-items:center}
.szl-status-label,.szl-section-label{color:#9ab5ce;font-size:11px;font-weight:800;letter-spacing:1.7px}
.szl-status-value{font-size:43px;font-weight:900;color:#b0ffe8}
.szl-reason{color:#a6c4df}
.szl-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-top:16px}
.szl-metrics div{background:rgba(114,166,189,.08);border-radius:12px;padding:14px}
.szl-metrics strong{display:block;font-size:28px;color:#ecf7ff}
.szl-metrics span{font-size:11px;color:#9dc2d1}
.szl-caveat{font-size:12px!important;line-height:1.6;color:#91a9bd!important;margin-top:12px}
.szl-table{border-collapse:collapse;width:100%;font-size:12px}
.szl-table th{text-align:left;color:#82cbcb;border-bottom:1px solid #335269;padding:10px 8px}
.szl-table td{padding:12px 8px;border-bottom:1px solid rgba(90,137,169,.16);color:#dce9f7}
.szl-table td small{display:block;color:#7fa4bc;margin-top:3px}
.szl-pill{padding:6px 8px;border:1px solid #467c93;border-radius:999px}
.szl-math-number{color:#62e9be;font-size:74px;font-weight:900;line-height:1.2}
@media(max-width:750px){.szl-hero{padding:24px}.szl-metrics{grid-template-columns:repeat(2,1fr)}.szl-table{font-size:10px}}
"""


def build_ui():
    """Build an interactive Gradio product; import UI dependencies only here."""
    import gradio as gr

    with gr.Blocks(title="SZL | Science Gate Studio") as demo:
        gr.HTML(
            '<div class="szl-hero"><div class="szl-kicker">SZL HOLDINGS / KHIPU RESEARCH SYSTEMS</div>'
            '<h1>SCIENCE<br/>GATE STUDIO</h1>'
            '<p>Try a real, fail-closed scientific-evidence verifier. '
            'Break a synthetic dataset. Watch the rule fail, inspect the falsifier '
            'and export its complete machine receipt.</p>'
            '<div class="szl-badges"><span>REAL PYTHON ENGINE</span>'
            '<span>NEGATIVE CONTROL WITNESSES</span><span>SOURCE-BOUND EVIDENCE</span>'
            '<span>NO PRIVATE LAB INPUTS</span></div></div>'
        )
        with gr.Tab("01 / LIVE VERIFIER"):
            gr.Markdown(
                "### Run the actual scientific-evidence gate\n"
                "Choose a sealed synthetic case. Every run calls the canonical CLI "
                "in a fresh, isolated temporary workspace. No model judge or "
                "hardcoded pass result. **Do not submit private laboratory or patient data.**"
            )
            scenario = gr.Dropdown(
                choices=list(SCENARIOS), value=next(iter(SCENARIOS)),
                label="Synthetic experiment / fault injection",
            )
            btn = gr.Button("VERIFY & BUILD RECEIPT", variant="primary")
            dashboard = gr.HTML()
            trace = gr.HTML()
            report = gr.Markdown(label="Actual verifier report")
            export = gr.File(label="Download synthetic fixture + original machine receipt (ZIP)")
            btn.click(
                fn=_render_case, inputs=[scenario],
                outputs=[dashboard, trace, report, export],
                api_name="verify_synthetic",
            )
        with gr.Tab("02 / LUTAR MATH LAB"):
            gr.Markdown(
                "### Canonical Lambda, deliberately separated from admission\n"
                "Experimental arithmetic demonstration of the equal-weight "
                "Lutar geometric mean. **These controls simulate facts and are not "
                "live signatures, releases, or a Lean kernel proof.**"
            )
            with gr.Row():
                axis_x = gr.Slider(0, 1, value=.8, step=.01, label="Evidence axis x")
                axis_y = gr.Slider(0, 1, value=.7, step=.01, label="Evidence axis y")
            with gr.Row():
                ci = gr.Checkbox(label="Required CI",value=False)
                source = gr.Checkbox(label="Immutable source parity",value=False)
                signed = gr.Checkbox(label="Receipt signature verified",value=False)
            with gr.Row():
                fresh = gr.Checkbox(label="Fresh evidence",value=False)
                runtime = gr.Checkbox(label="Runtime identity",value=False)
                approval = gr.Checkbox(label="Operator approval",value=False)
            math_button = gr.Button("EVALUATE WHAT-IF",variant="secondary")
            math_html = gr.HTML()
            math_button.click(
                fn=_render_lutar,
                inputs=[axis_x,axis_y,ci,source,signed,fresh,runtime,approval],
                outputs=[math_html], api_name="lutar_what_if",
            )
        with gr.Tab("03 / SOURCE & METHOD"):
            gr.Markdown(
                "### The product does not decide scientific truth\n\n"
                "**Source:** [scientific-evidence-gate]("+SOURCE_CODE+") — the same "
                "Python verifier used by the CLI.  \n"
                "**Math reference:** ["+SOURCE_MATH+"]("
                "https://github.com/szl-holdings/lutar-lean/tree/"
                "c2ca813fca00ecf58bcc5f505f2aa4237fbf2481).  \n"
                "**Method:** Every check is bound to a PLAN and a ledger entry. "
                "A synthetic negative control proves a given checker had an "
                "opportunity to reject a known-bad input. The resulting ZIP "
                "includes the fixed fixture bytes and all original report/receipt "
                "files, so a second operator can replay the example.  \n"
                "**Limits:** The controls in Tab 02 are hypothetical. No lab's "
                "private records are accepted or exposed. The ZIP is synthetic "
                "and is not an independently signed chain head, a trained model, "
                "a biological validation, or a production release.  \n"
                "**Safety:** Never paste patient, unpublished experimental, "
                "credential, or other restricted data into a public demo."
            )
        gr.Markdown(
            "**SZL Holdings** · Control before action. Evidence after. "
            "A valid demo is not a biological or production certification."
        )
    demo.queue(default_concurrency_limit=2, max_size=16)
    return demo


def main() -> None:
    build_ui().launch(css=STYLE, server_name="0.0.0.0", server_port=int(os.getenv("PORT", "7860")))


if __name__ == "__main__":
    main()
