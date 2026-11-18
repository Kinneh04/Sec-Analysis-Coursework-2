"""Deployed V8 blend: frozen EMBER2024 (R1) + Binary Ninja model, for the dashboard and the command line.

Decision rule (src.v8.blend.decide, frozen in artifacts/v8/freeze/freeze_manifest.json):
  covered files (cap6 and hl6 status ok/partial):  m = logit(R1) + w * logit(BN) - t_blend
  other files:                                     m = logit(R1) - logit(thr_R1)      (R1's own decision)
  malicious  <=>  m >= 0

Display scale: probability = sigmoid(m + logit(thr_R1)). This is a monotone rescaling of the margin so a
single threshold (thr_R1) applies to every file; on uncovered files it equals R1's raw score. It is NOT a
calibrated probability for covered files.

Static analysis only; files are never executed.

  python -m src.v8.deploy path\\to\\file.exe
  python -m src.v8.deploy --recursive C:\\Suspicious\\bin --no-bn --summary
  python -m src.v8.deploy --manifest files.csv --output scores.jsonl
  python -m src.v8.deploy --download-model          # fetch EMBER2024_PE.model if missing, replace it if its hash is wrong
                                                    # (with SA2_EMBER_DOWNLOAD=0: verify only, never download)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pickle
import sys
import time
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
MODEL_TAG = "v8"
ENGINE_BLEND = "v8_blend"
ENGINE_R1 = "ember2024"
CANDIDATE = Path("artifacts/v8/models/candidate.pkl")
R1_PKL = Path("artifacts/v8/models/R1.pkl")
FREEZE = Path("artifacts/v8/freeze/freeze_manifest.json")
# Same location src.v4.ember.pretrained_model() reads (thrember.download_models() nests the path).
EMBER_MODEL = Path("artifacts/ember2024/models/artifacts/ember2024/models/EMBER2024_PE.model")
EMBER_REPO = "joyce8/EMBER2024-benchmark-models"
EMBER_REVISION = "e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2"  # Hugging Face commit of 2025-06-10 (Apache-2.0)
EMBER_URL = f"https://huggingface.co/{EMBER_REPO}/resolve/{EMBER_REVISION}/EMBER2024_PE.model"
EMBER_SHA256 = "4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99"  # Hugging Face LFS oid
EMBER_SIZE = 3_756_042
PE_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ""}


class ModelMissing(RuntimeError):
    """EMBER2024_PE.model is not usable. kind: missing | wrong_hash | download_failed (subclasses below)."""

    kind = "missing"


class ModelHashMismatch(ModelMissing):
    kind = "wrong_hash"


class ModelDownloadFailed(ModelMissing):
    kind = "download_failed"


def _abs(p: Path) -> Path:
    return p if p.is_absolute() else ROOT / p


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _logit(x: float) -> float:
    """Same clipping as src.v4.experiment._logit."""
    x = min(max(float(x), 1e-7), 1 - 1e-7)
    return math.log(x / (1 - x))


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x)) if x >= 0 else math.exp(x) / (1 + math.exp(x))


# ------------------------------------------------------------------ EMBER2024 model file

def _download_allowed() -> bool:
    return os.environ.get("SA2_EMBER_DOWNLOAD", "1").strip().lower() not in ("0", "off", "false", "no")


def ensure_ember_model(*, download: bool | None = None, replace_bad: bool = False, quiet: bool = False) -> Path:
    """Return the verified EMBER2024_PE.model path.

    download=None reads SA2_EMBER_DOWNLOAD (default on); False never downloads. A missing file is downloaded when allowed.
    A file with the wrong hash is never used: it is replaced only with replace_bad=True (the explicit --download-model)
    and downloading allowed; otherwise ModelHashMismatch names the fix. A download goes to <name>.part, is verified, and
    only then replaces the target (os.replace), so a failed download leaves an existing file untouched.
    Errors: ModelMissing (missing, downloading off), ModelHashMismatch, ModelDownloadFailed.
    """
    path = _abs(EMBER_MODEL)
    allowed = _download_allowed() if download is None else bool(download)
    env_off = download is None and not allowed
    replacing = path.is_file()
    if replacing:
        got = _sha256(path)
        if got == EMBER_SHA256:
            return path
        if not (replace_bad and allowed):
            fix = "run 'python -m src.v8.deploy --download-model' to replace it" + (" (unset SA2_EMBER_DOWNLOAD first)" if env_off else "")
            raise ModelHashMismatch(f"{EMBER_MODEL} exists but its SHA-256 is {got}, not {EMBER_SHA256}: {fix}, or copy a "
                                    f"correct EMBER2024_PE.model over it.")
    elif not allowed:
        hint = (", or unset SA2_EMBER_DOWNLOAD and run 'python -m src.v8.deploy --download-model' (needs internet access to "
                "huggingface.co once)") if env_off else ""
        raise ModelMissing(f"Missing {EMBER_MODEL} and downloading is off ({'SA2_EMBER_DOWNLOAD=0' if env_off else 'download=False'}). "
                           f"Copy EMBER2024_PE.model (SHA-256 {EMBER_SHA256}) there from {EMBER_URL}{hint}.")
    _download_model(path, replacing=replacing, quiet=quiet)
    return path


def _discard(p: Path) -> None:
    try:
        p.unlink(missing_ok=True)
    except OSError:
        pass


def _download_model(path: Path, *, replacing: bool, quiet: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    part = path.with_name(path.name + ".part")
    kept = " The existing file (wrong hash) was left in place and is still refused." if replacing else ""
    if not quiet:
        print(f"[sa2] {'replacing' if replacing else 'downloading'} EMBER2024_PE.model ({EMBER_SIZE / 1e6:.1f} MB) from "
              f"huggingface.co ...", file=sys.stderr, flush=True)
    h = hashlib.sha256()
    try:
        req = urllib.request.Request(EMBER_URL, headers={"User-Agent": "sa2-scan"})
        with urllib.request.urlopen(req, timeout=60) as r, part.open("wb") as out:
            for chunk in iter(lambda: r.read(1 << 16), b""):
                h.update(chunk)
                out.write(chunk)
    except Exception as e:
        _discard(part)
        raise ModelDownloadFailed(f"Could not download {EMBER_URL}: {type(e).__name__}: {e}. Check internet access to "
                                  f"huggingface.co, or copy EMBER2024_PE.model (SHA-256 {EMBER_SHA256}) to {EMBER_MODEL} "
                                  f"by hand.{kept}") from e
    if h.hexdigest() != EMBER_SHA256:
        _discard(part)
        raise ModelDownloadFailed(f"The file downloaded from {EMBER_URL} has SHA-256 {h.hexdigest()}, expected {EMBER_SHA256}; "
                                  f"it was not used.{kept}")
    os.replace(part, path)


# ------------------------------------------------------------------ frozen bundle

def verify_freeze() -> list[str]:
    """Deployed files whose bytes differ from the V8 freeze manifest (CRLF/LF-only differences in code are accepted).

    Only files this deployment uses are checked: the two pickles and the frozen src/ modules. The manifest
    also lists research inputs (cohort manifests, docs, R2.pkl) that are not shipped; they are ignored.
    """
    frozen = json.loads(_abs(FREEZE).read_text(encoding="utf-8"))["files"]
    bad = []
    for f, digest in frozen.items():
        if not (f.startswith("src/") or f in (CANDIDATE.as_posix(), R1_PKL.as_posix())):
            continue
        p = _abs(Path(f))
        if not p.is_file():
            bad.append(f)
            continue
        b = p.read_bytes()
        cands = {b}
        if f.startswith("src/"):
            lf = b.replace(b"\r\n", b"\n")
            cands |= {lf, lf.replace(b"\n", b"\r\n")}
        if not any(hashlib.sha256(c).hexdigest() == digest for c in cands):
            bad.append(f)
    return bad


def load_bundle(*, verify: bool = True, download: bool | None = None) -> dict[str, Any]:
    """Frozen V8 candidate + R1 threshold + EMBER2024 booster. verify=True refuses modified model pickles."""
    import lightgbm as lgb

    bad = verify_freeze()
    if verify and any("/models/" in b for b in bad):
        raise SystemExit(f"V8 freeze verification failed: {bad}")
    with _abs(CANDIDATE).open("rb") as fh:
        cand = pickle.load(fh)
    with _abs(R1_PKL).open("rb") as fh:
        r1 = pickle.load(fh)
    if abs(float(r1["threshold"]) - float(cand["thr_r1"])) > 1e-12:
        raise SystemExit("R1.pkl and candidate.pkl disagree on thr_R1")
    booster = lgb.Booster(model_file=str(ensure_ember_model(download=download)))
    if booster.num_feature() != 2568:
        raise SystemExit(f"EMBER2024 model expects {booster.num_feature()} features, not 2568")
    return {"tag": MODEL_TAG, "candidate": cand, "cols": list(cand["cols"]), "w": float(cand["w"]),
            "t_blend": float(cand["t_blend"]), "thr_r1": float(cand["thr_r1"]), "r1_model": booster,
            "r1_model_file": r1["model_file"], "freeze_bad": bad}


# ------------------------------------------------------------------ features

@lru_cache(maxsize=1)
def _extractor() -> Any:
    import thrember

    return thrember.PEFeatureExtractor()


def ember_vector(raw: bytes) -> np.ndarray:
    """2568-dim EMBER v3 vector (src.v4.ember._worker equivalent). Works for non-PE input too (is_pe = 0)."""
    vec = np.asarray(_extractor().feature_vector(raw), dtype=np.float32)
    if vec.shape[0] != 2568:
        raise ValueError(f"bad_dim:{vec.shape[0]}")
    return vec


def ember_is_pe(vec: np.ndarray) -> bool:
    return bool(vec[2] == 1)  # em_general_is_pe: thrember's pefile.PE() parse succeeded


# ------------------------------------------------------------------ scoring

def score_vector(bundle: dict[str, Any], vec: np.ndarray, bn_features: dict[str, float] | None = None,
                 *, contributions: bool = True) -> dict[str, Any]:
    """Score one EMBER vector, with Binary Ninja features when available (None = uncovered, R1 fallback).

    Returns r1_score, r1_logit, bn_score (covered only), covered, blend_margin (m), decision, probability
    (display scale), display_shift = logit(thr_R1), thresholds, and when contributions=True:
      contrib: [(feature, value, contribution)] for all EMBER features (+ w * BN-model SHAP on covered files)
      contrib_base: so that contrib_base + sum(contributions) == blend_margin + display_shift == logit(probability)
      contrib_parts: {"r1_expected_value", "bn_expected_value_x_w", "offset", "clip_adjust"} that add up to contrib_base.
    """
    from src.v8 import blend
    from src.v8.ember_map import ember_feature_names

    cand, cols, w, t_blend, thr_r1 = bundle["candidate"], bundle["cols"], bundle["w"], bundle["t_blend"], bundle["thr_r1"]
    x = vec.reshape(1, -1).astype(np.float64)
    r1 = float(bundle["r1_model"].predict(x)[0])
    covered = bn_features is not None
    row = {"r1_logit": _logit(r1), **{c: (float(bn_features[c]) if covered and c in bn_features else np.nan) for c in cols}}
    df = pd.DataFrame([row], columns=["r1_logit", *cols])
    decision, score = blend.decide(cand, df, np.array([covered]))
    m = float(score[0])
    shift = _logit(thr_r1)
    out: dict[str, Any] = {
        "r1_score": r1, "r1_logit": row["r1_logit"], "covered": covered, "blend_margin": m, "decision": bool(decision[0]),
        "display_shift": shift, "probability": _sigmoid(m + shift), "threshold": thr_r1, "w": w, "t_blend": t_blend,
        "bn_score": None, "bn_logit": None, "bn_missing_columns": [],
    }
    if covered:
        xb = df[cols].to_numpy(dtype=float)
        out["bn_score"] = float(cand["model"].predict_proba(xb)[0, 1])
        out["bn_logit"] = _logit(out["bn_score"])
        out["bn_missing_columns"] = [c for c in cols if c not in bn_features]
    if not contributions:
        return out
    ce = bundle["r1_model"].predict(x, pred_contrib=True)[0]  # raw-score (log-odds) SHAP, last entry = expected value
    names = ember_feature_names()
    contrib = [(names[i], float(vec[i]), float(ce[i])) for i in range(len(names))]
    parts = {"r1_expected_value": float(ce[-1]), "bn_expected_value_x_w": 0.0, "offset": 0.0}
    raw = float(ce.sum())
    if covered:
        cb = cand["model"].predict(xb, pred_contrib=True)[0]
        contrib += [(c, float(xb[0, j]), w * float(cb[j])) for j, c in enumerate(cols)]
        parts["bn_expected_value_x_w"] = w * float(cb[-1])
        parts["offset"] = -t_blend + shift
        raw += w * float(cb.sum()) + parts["offset"]
    target = m + shift
    parts["clip_adjust"] = target - raw  # non-zero only when R1 or BN probability hit the 1e-7 logit clip
    out["contrib"] = contrib
    out["contrib_base"] = parts["r1_expected_value"] + parts["bn_expected_value_x_w"] + parts["offset"] + parts["clip_adjust"]
    out["contrib_parts"] = parts
    return out


def score_file(path: Path, bundle: dict[str, Any] | None = None, *, use_bn: bool | None = None,
               raw: bytes | None = None, contributions: bool = False, bn_cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Full static scoring of one file: EMBER vector, Binary Ninja (when enabled and reachable), blend decision."""
    from src.v8 import bn_live

    t0 = time.perf_counter()
    bundle = bundle or load_bundle(verify=False)
    raw = path.read_bytes() if raw is None else raw
    sha = hashlib.sha256(raw).hexdigest()
    try:
        vec = ember_vector(raw)
    except Exception as e:
        return {"path": str(path), "sha256": sha, "error": f"ember_failed:{type(e).__name__}: {str(e)[:300]}"}
    if not ember_is_pe(vec):
        return {"path": str(path), "sha256": sha, "error": "pe_parse_failed"}
    t_em = time.perf_counter()
    cfg = dict(bn_cfg or bn_live.settings())
    if use_bn is False:
        cfg["enabled"] = False
    bn = bn_live.extract(path, sha, cfg)
    t_bn = time.perf_counter()
    s = score_vector(bundle, vec, bn["features"] if bn["covered"] else None, contributions=contributions)
    s.update(path=str(path), sha256=sha, vector=vec, bn=bn, decision_path="blend" if bn["covered"] else "r1_fallback",
             timings_ms={"ember": round((t_em - t0) * 1000), "bn": round((t_bn - t_em) * 1000),
                         "score": round((time.perf_counter() - t_bn) * 1000)})
    return s


# ------------------------------------------------------------------ CLI

def _iter_paths(paths: list[Path], recursive: bool) -> Iterator[Path]:
    for root in paths:
        if root.is_file():
            yield root
        elif root.is_dir():
            for p in (root.rglob("*") if recursive else root.iterdir()):
                if p.is_file() and p.suffix.lower() in PE_SUFFIXES:
                    yield p


def _public(s: dict[str, Any]) -> dict[str, Any]:
    if "error" in s:
        return s
    bn = s["bn"]
    return {"path": s["path"], "sha256": s["sha256"], "model_tag": MODEL_TAG, "flagged": s["decision"],
            "probability": s["probability"], "threshold": s["threshold"], "blend_margin": s["blend_margin"],
            "decision_path": s["decision_path"], "r1_score": s["r1_score"], "r1_flagged": s["r1_score"] >= s["threshold"],
            "bn_score": s["bn_score"], "bn_reason": bn["reason"], "cap6_status": bn["cap6_status"], "hl6_status": bn["hl6_status"],
            "timings_ms": s["timings_ms"]}


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except ModelMissing as e:  # missing/unverifiable EMBER2024_PE.model: one clear line, no traceback
        print(f"[error] EMBER2024 model not available ({e.kind.replace('_', ' ')}): {e}", file=sys.stderr)
        return 2


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="Files or directories to score")
    ap.add_argument("--manifest", type=Path, help="CSV/parquet with a path (or relative_path) column")
    ap.add_argument("--recursive", action="store_true")
    ap.add_argument("--verify-freeze", action="store_true", help="Also require the frozen src/ modules to match the V8 manifest")
    ap.add_argument("--no-bn", action="store_true", help="Skip Binary Ninja (R1 fallback for every file)")
    ap.add_argument("--output", type=Path, help="Write JSON lines")
    ap.add_argument("--summary", action="store_true", help="Print counts only")
    ap.add_argument("--download-model", action="store_true",
                    help="Make sure a verified EMBER2024_PE.model is present: download it if missing, replace it if its hash is "
                         "wrong (SA2_EMBER_DOWNLOAD=0: verify only, never download), then exit")
    args = ap.parse_args(argv)
    if args.download_model:
        print(ensure_ember_model(download=None, replace_bad=True))
        return 0
    if not args.paths and args.manifest is None:
        ap.error("provide paths or --manifest")
    bundle = load_bundle(verify=True)
    if args.verify_freeze and bundle["freeze_bad"]:
        raise SystemExit(f"V8 freeze verification failed: {bundle['freeze_bad']}")
    if args.manifest:
        m = pd.read_csv(args.manifest) if args.manifest.suffix.lower() == ".csv" else pd.read_parquet(args.manifest)
        targets = [Path(str(p)) for p in m["path" if "path" in m.columns else "relative_path"]]
    else:
        targets = list(_iter_paths([Path(p) for p in args.paths], args.recursive))
    scored = []
    for p in targets:
        try:
            scored.append(_public(score_file(p, bundle, use_bn=False if args.no_bn else None)))
        except OSError as e:
            scored.append({"path": str(p), "error": f"read_failed:{type(e).__name__}"})
    if args.summary:
        ok = [s for s in scored if "error" not in s]
        print(json.dumps({"model_tag": MODEL_TAG, "scored": len(ok), "errors": len(scored) - len(ok),
                          "flagged": sum(s["flagged"] for s in ok), "flagged_r1": sum(s["r1_flagged"] for s in ok),
                          "bn_covered": sum(s["decision_path"] == "blend" for s in ok)}, indent=2))
    else:
        for s in scored:
            print(json.dumps(s, default=str))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as fh:
            for s in scored:
                fh.write(json.dumps(s, default=str) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
