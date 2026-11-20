"""SA2 Scan: analyst console over the frozen V8 blend (EMBER2024 + Binary Ninja model; static analysis only).

  .venv\\Scripts\\python.exe -m src.webscan.app --port 8000
"""

from __future__ import annotations

import argparse
import csv
import hmac
import io
import json
import math
import os
import queue
import re
import secrets
import stat
import statistics
import sys
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from functools import lru_cache, wraps
from pathlib import Path
from typing import Any

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for

from src.common.sqlite_db import DB
from src.webscan import explain, scanner

ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 50 * 1024 * 1024
ONLINE_SECONDS = 90
# Borderline band: below the threshold but at or above EMBER2024's 5% training-FPR operating point
# (explain.reference()["r1_operating_points"]["fpr_0.05"]). Triage aid only, not a measured operating point of the blend.
BORDERLINE_FALLBACK = 0.10
REASONS = {"covered": "Binary Ninja features used (V8 blend)", "bn_disabled": "Binary Ninja disabled (SA2_BN=0)",
           "bn_busy": "Binary Ninja busy (in use by another scan)", "bn_unreachable": "Binary Ninja not reachable", "bn_too_large": "File too large for Binary Ninja",
           "bn_timeout": "Binary Ninja timed out", "bn_error": "Binary Ninja error", "bn_unusable": "Binary Ninja features unusable",
           "legacy": "Old V3.2 report (re-scan pending)", "none": "Not scored"}
ENGINE_LABELS = {scanner.ENGINE_BLEND: "V8 blend", scanner.ENGINE_R1: "EMBER2024"}
EVIDENCE = (("V8 blind", Path("artifacts/v8/blind/blind_results.json")),
            ("V9 replication", Path("artifacts/v9/blind/replication_results.json")),
            ("V10 replication", Path("artifacts/v10/blind/replication_results.json")))
DISPOSITIONS = {"": "Unreviewed", "confirmed": "Confirmed malicious", "false_positive": "False positive",
                "benign_ok": "Benign (verified)", "investigating": "Investigating"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS files(sha256 TEXT PRIMARY KEY, md5 TEXT, sha1 TEXT, imphash TEXT, size INTEGER, name TEXT,
  first_seen TEXT, last_seen TEXT, status TEXT, verdict TEXT, probability REAL, scan_ms INTEGER, report_json TEXT,
  disposition TEXT DEFAULT '', disposition_note TEXT, disposition_at TEXT);
CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY, sha256 TEXT, at TEXT, source TEXT, sensor_id TEXT,
  filename TEXT, meta_json TEXT);
CREATE INDEX IF NOT EXISTS ix_sub_sha ON submissions(sha256);
CREATE TABLE IF NOT EXISTS sensors(sensor_id TEXT PRIMARY KEY, hostname TEXT, agent_version TEXT, first_seen TEXT,
  last_heartbeat TEXT, stats_json TEXT);
CREATE TABLE IF NOT EXISTS sensor_stats(sensor_id TEXT, at TEXT, stats_json TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""
HEX = {64: "sha256", 40: "sha1", 32: "md5"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def age_seconds(ts: str | None) -> float:
    if not ts:
        return float("inf")
    return (datetime.now(timezone.utc) - datetime.fromisoformat(ts)).total_seconds()


def ago(ts: str | None) -> str:
    s = age_seconds(ts)
    if s == float("inf"):
        return "never"
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n:
            return f"{int(s // n)}{unit} ago"
    return "just now"


class BadUpload(Exception):
    def __init__(self, msg: str, code: int):
        super().__init__(msg)
        self.code = code


@lru_cache(maxsize=1)
def freeze_status() -> dict[str, Any]:
    try:
        return scanner.freeze_status()
    except Exception as e:  # missing or unreadable manifest
        return {"bad": [f"artifacts/v8/freeze/freeze_manifest.json ({type(e).__name__})"], "models_ok": False}


def borderline_cut(thr: float) -> tuple[float, str]:
    """Lower edge of the borderline band and where it came from."""
    v = (explain.reference() or {}).get("r1_operating_points", {}).get("fpr_0.05")
    if isinstance(v, (int, float)) and 0 < v < thr:
        return float(v), "EMBER2024 score at 5% training FPR"
    return BORDERLINE_FALLBACK, "fixed fallback (EMBER2024 operating points not available)"


def risk_band(p: float | None, thr: float, border: float = BORDERLINE_FALLBACK) -> str:
    if p is None:
        return "none"
    return "high" if p >= thr else ("elevated" if p >= border else "low")


def is_legacy(rep: dict[str, Any]) -> bool:
    """A stored report from before the V8 switch (V3.2 engines); re-scanned at startup."""
    return bool(rep) and rep.get("report_version", 1) < scanner.REPORT_VERSION


CSV_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(v: Any) -> Any:
    """Spreadsheet formula injection guard for CSV exports: a text cell (file name, signer, ...) that starts with = + - @
    tab or CR gets a leading single quote. Numbers, booleans and None are left as they are."""
    return "'" + v if isinstance(v, str) and v.startswith(CSV_FORMULA_START) else v


def path_reason(rep: dict[str, Any]) -> str:
    if is_legacy(rep):
        return "legacy"
    return ((rep.get("decision_path") or {}).get("reason")) or "none"


def engine_view(rep: dict[str, Any]) -> dict[str, Any]:
    """Per-report engine summary for templates: blend, R1, whether they disagree."""
    eng = {e.get("name"): e for e in rep.get("engines") or [] if isinstance(e, dict)}
    blend, r1 = eng.get(scanner.ENGINE_BLEND), eng.get(scanner.ENGINE_R1)
    disagree = bool(blend and r1 and bool(blend.get("flagged")) != bool(r1.get("flagged")))
    return {"blend": blend, "r1": r1, "disagree": disagree, "legacy": is_legacy(rep),
            "covered": bool(blend and blend.get("coverage") == "covered")}


@lru_cache(maxsize=1)
def frozen_params() -> dict[str, Any]:
    """w, t_blend, thr_R1 from the frozen candidate (no EMBER2024 model needed)."""
    import pickle
    try:
        with (ROOT / "artifacts/v8/models/candidate.pkl").open("rb") as fh:
            c = pickle.load(fh)
        return {k: float(c[k]) for k in ("w", "t_blend", "thr_r1")}
    except Exception:
        return {}


def _load_json(p: Path) -> dict[str, Any]:
    p = p if p.is_absolute() else ROOT / p
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def evidence() -> list[dict[str, Any]]:
    """V8 blind, V9 and V10 replication numbers, normalised from the tracked result files."""
    out = []
    for label, path in EVIDENCE:
        d = _load_json(path)
        if not d:
            continue
        if "arms" in d:  # V8 layout
            arms = {k: {**v.get("fixed", {}), "roc_auc": v.get("roc_auc")} for k, v in d["arms"].items()}
            paired = (d.get("paired") or {}).get("candidate_minus_R1", {})
            rule = (d.get("decision") or {}).get("R1", {}).get("beaten")
            cov = d.get("bn_coverage") or {}
            strict = None
        else:  # V9 / V10 layout
            pr = d.get("primary") or {}
            arms = {k: pr[k] for k in ("candidate", "R1", "R2") if k in pr}
            paired = pr.get("paired") or {}
            rule = (d.get("decision") or {}).get("R1", {}).get("met")
            cov = d.get("coverage") or {}
            strict = ((d.get("secondary") or {}).get("operating_points") or {}).get("0.0025")
        out.append({"label": label, "path": path.as_posix(), "run_at": (d.get("run_at") or "")[:10], "arms": arms,
                    "delta": paired.get("delta_tpr_b_minus_a"), "delta_ci": paired.get("delta_tpr_ci95"),
                    "rule_met": rule, "coverage": cov, "strict": strict})
    return out


def create_app(data_dir: Path | None = None, *, start_worker: bool = True, scan_fn=None) -> Flask:
    data_dir = Path(data_dir or ROOT / "artifacts" / "dashboard")
    qdir = data_dir / "quarantine"
    qdir.mkdir(parents=True, exist_ok=True)
    db = DB(data_dir / "scan.db", SCHEMA)
    cols = {r["name"] for r in db.q("PRAGMA table_info(files)")}
    for c, ddl in (("disposition", "TEXT DEFAULT ''"), ("disposition_note", "TEXT"), ("disposition_at", "TEXT")):
        if c not in cols:  # migrate databases created by the first version
            db.x(f"ALTER TABLE files ADD COLUMN {c} {ddl}")
    scan_fn = scan_fn or scanner.scan

    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=MAX_BYTES + 1024 * 1024, SESSION_COOKIE_SAMESITE="Lax", DB=db)
    for key, gen in (("secret_key", lambda: secrets.token_hex(32)), ("api_key", lambda: secrets.token_urlsafe(24)),
                     ("admin_password", lambda: secrets.token_urlsafe(9))):
        if not db.setting(key):
            db.set_setting(key, gen())
    app.secret_key = db.setting("secret_key")
    thr = scanner.thresholds()[scanner.ENGINE_BLEND]["threshold"]
    border, border_src = borderline_cut(thr)
    app.config.update(THRESHOLD=thr, BORDERLINE=border)
    notable = set().union(*(apis for _, _, apis, _ in explain.API_GROUPS.values()))
    app.jinja_env.globals.update(thr=thr, border=border, border_src=border_src, ago=ago, DISPOSITIONS=DISPOSITIONS,
                                 GROUPS=explain.GROUPS, NOTABLE=notable, REASONS=REASONS, ENGINE_LABELS=ENGINE_LABELS,
                                 ENGINE_BLEND=scanner.ENGINE_BLEND, ENGINE_R1=scanner.ENGINE_R1, MODEL_TAG=scanner.MODEL_TAG,
                                 pi=math.pi, cos=math.cos, sin=math.sin)
    jobs: queue.Queue[str] = queue.Queue()

    # ---------- core ----------
    def process(sha: str) -> None:
        db.x("UPDATE files SET status='scanning' WHERE sha256=?", (sha,))
        try:
            rep = scan_fn(qdir / sha)
        except Exception as e:  # keep the worker alive on any parser/model failure
            rep = {"verdict": "error", "error": f"{type(e).__name__}: {e}", "engines": [], "top_features": [], "pe": {},
                   "signals": [], "explanation": {}, "report_version": scanner.REPORT_VERSION}
        status = "error" if rep.get("verdict") == "error" else "done"
        db.x("UPDATE files SET status=?, verdict=?, probability=?, scan_ms=?, imphash=?, report_json=? WHERE sha256=?",
             (status, rep.get("verdict"), rep.get("probability"), rep.get("scan_ms"),
              (rep.get("pe") or {}).get("imphash"), json.dumps(rep, default=str), sha))

    def worker() -> None:
        while True:
            process(jobs.get())

    app.config["PROCESS"] = process

    def ingest(raw: bytes, filename: str, source: str, sensor_id: str | None = None, meta: dict | None = None) -> tuple[str, bool]:
        if len(raw) == 0:
            raise BadUpload("Empty file", 400)
        if len(raw) > MAX_BYTES:
            raise BadUpload("File larger than 50 MB", 413)
        if not scanner.is_pe(raw):
            raise BadUpload("Not a Windows PE file (no MZ header). SA2 models only analyse .exe / .dll / .sys files.", 415)
        h = scanner.hashes(raw)
        sha, t = h["sha256"], now()
        path = qdir / sha
        if not path.exists():
            path.write_bytes(raw)
            os.chmod(path, stat.S_IREAD)
        name = Path(filename or sha).name[:255]
        created = db.x("INSERT OR IGNORE INTO files(sha256, md5, sha1, size, name, first_seen, last_seen, status) "
                       "VALUES(?,?,?,?,?,?,?, 'queued')", (sha, h["md5"], h["sha1"], len(raw), name, t, t)) == 1
        if not created:
            db.x("UPDATE files SET last_seen=? WHERE sha256=?", (t, sha))
        db.x("INSERT INTO submissions(sha256, at, source, sensor_id, filename, meta_json) VALUES(?,?,?,?,?,?)",
             (sha, t, source, sensor_id, name, json.dumps(meta or {})))
        if created:
            jobs.put(sha)
        return sha, created

    def full_report(sha: str) -> dict[str, Any] | None:
        f = db.one("SELECT * FROM files WHERE sha256=?", (sha,))
        if not f:
            return None
        rep = json.loads(f.pop("report_json") or "{}")
        subs = db.q("SELECT at, source, sensor_id, filename, meta_json FROM submissions WHERE sha256=? ORDER BY id", (sha,))
        for s in subs:
            s["meta"] = json.loads(s.pop("meta_json") or "{}")
        r = {**f, **rep, "status": f["status"], "verdict": f["verdict"],
             "names": sorted({s["filename"] for s in subs if s["filename"]}), "submissions": subs}
        sigs = (rep.get("signals") or []) + explain.origin_signals(subs)
        r["all_signals"] = sigs
        r["assessment"] = explain.assessment(r, sigs) if f["status"] == "done" and not is_legacy(rep) else None
        r["view"] = engine_view(rep)
        r["path_reason"] = path_reason(rep) if f["status"] == "done" else ("none" if f["status"] == "error" else "pending")
        r["risk"] = row_risk(f, rep)
        return r

    def row_risk(f: dict[str, Any], rep: dict[str, Any]) -> str:
        if is_legacy(rep) and f.get("status") == "done":  # old V3.2 score is on another scale: use its verdict only
            return "high" if f.get("verdict") == "malicious" else "low"
        return risk_band(f.get("probability"), thr, border)

    def summarize(f: dict[str, Any]) -> dict[str, Any]:
        """Lightweight per-row view for tables (parses the stored report once)."""
        rep = json.loads(f.get("report_json") or "{}")
        sigs = rep.get("signals") or []
        top = next((r for r in (rep.get("explanation") or {}).get("top", [])
                    if (r["contribution"] > 0) == (f.get("verdict") == "malicious")), None)
        a = explain.assessment({**rep, "verdict": f.get("verdict"), "probability": f.get("probability")}, sigs) \
            if f.get("status") == "done" and not is_legacy(rep) else None
        chips = [s for s in sigs if s["severity"] in ("high", "medium") or s["id"].startswith("format_") or s["id"] == "signed_valid"][:4]
        signer = (rep.get("pe") or {}).get("signature", {})
        return {**{k: v for k, v in f.items() if k != "report_json"}, "risk": row_risk(f, rep), "legacy": is_legacy(rep),
                "path_reason": path_reason(rep) if f.get("status") == "done" else None, "disagree": engine_view(rep)["disagree"],
                "top_reason": top, "assessment": a, "chips": chips,
                "signer": signer.get("signer") if isinstance(signer, dict) and signer.get("status") == "Valid" else "",
                "pe_format": (rep.get("pe") or {}).get("format"), "is_dll": (rep.get("pe") or {}).get("is_dll")}

    def find(q: str) -> list[dict[str, Any]]:
        q = q.strip()
        col = HEX.get(len(q)) if re.fullmatch(r"[0-9a-fA-F]+", q or "x") else None
        if col:
            return db.q(f"SELECT * FROM files WHERE {col}=?", (q.lower(),))
        like = f"%{q}%"
        return db.q("SELECT DISTINCT f.* FROM files f LEFT JOIN submissions s ON s.sha256=f.sha256 "
                    "WHERE f.name LIKE ? OR s.filename LIKE ? OR f.imphash=? ORDER BY f.last_seen DESC LIMIT 200",
                    (like, like, q))

    # ---------- auth ----------
    def require_key(fn):
        @wraps(fn)
        def inner(*a, **kw):
            if not hmac.compare_digest(request.headers.get("X-API-Key", ""), db.setting("api_key") or ""):
                return jsonify(error="invalid or missing X-API-Key"), 401
            return fn(*a, **kw)
        return inner

    def login_required(fn):
        @wraps(fn)
        def inner(*a, **kw):
            if not session.get("admin"):
                return redirect(url_for("login", next=request.full_path.rstrip("?")))
            return fn(*a, **kw)
        return inner

    @app.context_processor
    def ctx():
        fs = freeze_status()
        return {"signed_in": bool(session.get("admin")), "models_ok": fs["models_ok"],
                "pending_count": db.val("SELECT COUNT(*) FROM files WHERE status IN ('queued','scanning')") or 0}

    @app.template_filter("fromjson")
    def fromjson(s):
        return json.loads(s or "{}")

    @app.template_filter("filesize")
    def filesize(n):
        return explain.fmt_value(float(n or 0), "bytes")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            if hmac.compare_digest(request.form.get("password", ""), os.environ.get("SA2_ADMIN_PASSWORD") or db.setting("admin_password")):
                session["admin"] = True
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("home"))
            flash("Wrong password.", "error")
        return render_template("login.html")

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/admin")
    @app.get("/admin/<path:_rest>")
    def legacy_admin(_rest: str = ""):
        return redirect(url_for("overview"))

    # ---------- overview ----------
    def sensors_with_health() -> list[dict[str, Any]]:
        rows = db.q("SELECT * FROM sensors ORDER BY last_heartbeat DESC")
        for s in rows:
            s["online"] = age_seconds(s["last_heartbeat"]) <= ONLINE_SECONDS
            s["stats"] = json.loads(s.pop("stats_json") or "{}")
        return rows


    def correlations(done: list[dict[str, Any]]) -> dict[str, Any]:
        """Cross-file views for the dashboard: engine agreement, score over time, signal co-occurrence, reason heatmap."""
        rows = []
        for f in done:
            rep = json.loads(f["report_json"] or "{}")
            sig = (rep.get("pe") or {}).get("signature") or {}
            risk = row_risk(f, rep)
            cls = "malicious" if f["verdict"] == "malicious" else ("borderline" if risk == "elevated" else "benign")
            rows.append({"f": f, "rep": rep, "view": engine_view(rep), "reason": path_reason(rep), "cls": cls,
                         "signed": isinstance(sig, dict) and sig.get("status") == "Valid",
                         "sigs": {s["id"] for s in rep.get("signals") or []}})
        # Engine agreement on Binary-Ninja-covered files only: on fallback files the blend IS EMBER2024 (identical scores).
        pts = [{"x": r["view"]["blend"].get("probability"), "y": r["view"]["r1"].get("probability"), "cls": r["cls"], "signed": r["signed"],
                "name": r["f"]["name"], "sha": r["f"]["sha256"], "disagree": r["view"]["disagree"]}
               for r in rows if r["view"]["covered"] and r["view"]["r1"]
               and r["view"]["blend"].get("probability") is not None and r["view"]["r1"].get("probability") is not None]
        paths = Counter(r["reason"] for r in rows)
        n_fallback = sum(n for k, n in paths.items() if k.startswith("bn_"))
        pearson = None
        if len(pts) >= 3:
            xs, ys = [q["x"] for q in pts], [q["y"] for q in pts]
            mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
            sxy = sum((a - mx) * (b - my) for a, b in zip(xs, ys))
            sx, sy = sum((a - mx) ** 2 for a in xs) ** .5, sum((b - my) ** 2 for b in ys) ** .5
            pearson = sxy / (sx * sy) if sx and sy else None
        agree = sum(1 for q in pts if not q["disagree"])
        # score over time
        ts = sorted(rows, key=lambda r: r["f"]["first_seen"] or "")
        timeline, labels = [], []
        if ts:
            t0 = datetime.fromisoformat(ts[0]["f"]["first_seen"]).timestamp()
            t1 = datetime.fromisoformat(ts[-1]["f"]["first_seen"]).timestamp()
            span = max(t1 - t0, 1)
            for i, r in enumerate(ts):
                t = (datetime.fromisoformat(r["f"]["first_seen"]).timestamp() - t0) / span if t1 > t0 else (i + .5) / len(ts)
                timeline.append({"t": t, "y": r["f"]["probability"] or 0, "cls": r["cls"], "signed": r["signed"],
                                 "name": r["f"]["name"], "sha": r["f"]["sha256"], "when": r["f"]["first_seen"].replace("T", " ")[:16]})
            fmt = (lambda s: s[5:16].replace("T", " ")) if t1 - t0 < 86400 * 2 else (lambda s: s[:10])
            labels = [(0, fmt(ts[0]["f"]["first_seen"])), (1, fmt(ts[-1]["f"]["first_seen"]))]
            if t1 > t0:
                labels.insert(1, (0.5, fmt(datetime.fromtimestamp((t0 + t1) / 2, timezone.utc).isoformat())))
        # signal co-occurrence + flag rate
        counts = Counter(s for r in rows for s in r["sigs"])
        top = [k for k, _ in counts.most_common(9)]
        titles = {}
        for r in rows:
            for s in r["rep"].get("signals") or []:
                titles.setdefault(s["id"], explain.generic_title(s))
        co = [[sum(1 for r in rows if a in r["sigs"] and b in r["sigs"]) for b in top] for a in top]
        flag_rate = {k: sum(1 for r in rows if k in r["sigs"] and r["cls"] == "malicious") / counts[k] for k in top}
        base_rate = sum(1 for r in rows if r["cls"] == "malicious") / len(rows) if rows else 0
        # reason-group heatmap for the highest-scoring files
        order = [g for g in explain.GROUPS if g != "size"]  # "size" may not exist in every GROUPS version; harmless
        hot = sorted(rows, key=lambda r: -(r["f"]["probability"] or 0))[:12]
        heat = []
        for r in hot:
            gm = {g["group"]: g["contribution"] for g in (r["rep"].get("explanation") or {}).get("groups", [])}
            heat.append({"name": r["f"]["name"], "sha": r["f"]["sha256"], "p": r["f"]["probability"] or 0, "cls": r["cls"],
                         "cells": [gm.get(g, 0.0) for g in order], "nsis": "format_nsis" in r["sigs"], "signed": r["signed"]})
        hmax = max([abs(c) for h in heat for c in h["cells"]] + [0.01])
        return {"scatter": pts, "pearson": pearson, "agree": agree, "n_covered": paths.get("covered", 0), "n_fallback": n_fallback,
                "paths": sorted(paths.items(), key=lambda kv: -kv[1]), "timeline": timeline, "labels": labels,
                "co_ids": top, "co_titles": [titles.get(k, k) for k in top], "co": co, "co_counts": [counts[k] for k in top],
                "flag_rate": [flag_rate[k] for k in top], "base_rate": base_rate,
                "heat": heat, "heat_groups": [explain.GROUPS[g][0] for g in order], "hmax": hmax}

    @app.get("/")
    @login_required
    def home():
        files = db.q("SELECT * FROM files")
        stats = {"total": len(files), "flagged": sum(1 for f in files if f["verdict"] == "malicious"),
                 "review": sum(1 for f in files if not f["disposition"] and (f["verdict"] == "malicious" or (f["probability"] or 0) >= border)),
                 "sensors": sum(s["online"] for s in sensors_with_health())}
        recent = [summarize(f) for f in db.q("SELECT * FROM files ORDER BY last_seen DESC LIMIT 6")]
        return render_template("home.html", stats=stats, recent=recent)

    @app.get("/dashboard")
    @login_required
    def overview():
        files = db.q("SELECT * FROM files")
        done = [f for f in files if f["status"] == "done"]
        today = datetime.now(timezone.utc).date()
        days = [(today - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
        per_day = {d: Counter() for d in days}
        for r in db.q("SELECT substr(s.at,1,10) day, f.verdict v, f.probability p, f.status st FROM submissions s "
                      "JOIN files f ON f.sha256=s.sha256 WHERE s.at >= ?", (days[0],)):
            if r["day"] in per_day:
                k = "pending" if r["st"] in ("queued", "scanning") else ("error" if r["st"] == "error" else
                    ("malicious" if r["v"] == "malicious" else ("borderline" if border <= (r["p"] or 0) < thr else "benign")))
                per_day[r["day"]][k] += 1
        mal = [f for f in done if f["verdict"] == "malicious"]
        bline = [f for f in done if f["verdict"] == "benign" and border <= (f["probability"] or 0) < thr]
        sensors = sensors_with_health()
        ms = [f["scan_ms"] for f in done if f["scan_ms"] is not None]
        kpi = {
            "total": len(files), "today": sum(1 for f in files if (f["first_seen"] or "")[:10] == today.isoformat()),
            "malicious": len(mal), "borderline": len(bline),
            "benign": sum(1 for f in done if f["verdict"] == "benign") - len(bline),
            "pending": sum(1 for f in files if f["status"] in ("queued", "scanning")),
            "errors": sum(1 for f in files if f["status"] == "error"),
            "unreviewed": sum(1 for f in mal + bline if not f["disposition"]),
            "false_positives": sum(1 for f in files if f["disposition"] == "false_positive"),
            "confirmed": sum(1 for f in files if f["disposition"] == "confirmed"),
            "sensors_online": sum(s["online"] for s in sensors), "sensors_total": len(sensors),
            "median_ms": round(statistics.median(ms)) if ms else None,
        }
        spark = {k: [per_day[d][k] for d in days] for k in ("malicious", "benign", "borderline")}
        spark["total"] = [sum(per_day[d].values()) for d in days]
        attention = sorted((summarize(f) for f in files if not f["disposition"] and (
            f["verdict"] == "malicious" or f["status"] == "error" or (f["verdict"] == "benign" and border <= (f["probability"] or 0) < thr))),
            key=lambda s: -(s["probability"] or 0))[:8]
        group_push: dict[str, list[float]] = defaultdict(list)
        sig_counts: Counter = Counter()
        sig_flagged: Counter = Counter()
        sig_titles: dict[str, str] = {}
        bins = [0] * 20
        for f in done:
            rep = json.loads(f["report_json"] or "{}")
            if f["verdict"] == "malicious":
                for g in (rep.get("explanation") or {}).get("groups", []):
                    if g.get("contribution", 0) > 0 and g.get("group") in explain.GROUPS:
                        group_push[g["group"]].append(g["contribution"])
            for s in rep.get("signals") or []:
                key = s["id"]
                sig_counts[key] += 1
                sig_titles.setdefault(key, explain.generic_title(s))
                if f["verdict"] == "malicious":
                    sig_flagged[key] += 1
            if f["probability"] is not None and not is_legacy(rep):
                bins[min(max(int(f["probability"] * 20), 0), 19)] += 1
        reasons_agg = sorted(((explain.GROUPS[g][0], sum(v) / max(len(mal), 1), len(v)) for g, v in group_push.items()), key=lambda x: -x[1])[:6]
        corr = correlations(done)
        signals_agg = [(sig_titles[k], n, sig_flagged[k]) for k, n in sig_counts.most_common(8)]
        recent = db.q("SELECT s.at, s.source, s.sensor_id, s.filename, f.sha256, f.status, f.verdict, f.probability "
                      "FROM submissions s JOIN files f ON f.sha256=s.sha256 ORDER BY s.id DESC LIMIT 10")
        mix = [("malicious", "Malicious", kpi["malicious"]), ("borderline", "Borderline", kpi["borderline"]),
               ("benign", "Benign", kpi["benign"]), ("error", "Error", kpi["errors"]), ("pending", "Pending", kpi["pending"])]
        return render_template("overview.html", st=kpi, per_day=per_day, days=days, spark=spark, attention=attention,
                               reasons_agg=reasons_agg, signals_agg=signals_agg, bins=bins, recent=recent, mix=mix,
                               sensors=sensors[:6], n_done=len(done), corr=corr,
                               day_max=max([sum(c.values()) for c in per_day.values()] + [1]))

    # ---------- analyze / search ----------
    @app.get("/analyze")
    @login_required
    def analyze():
        return redirect(url_for("home"))

    @app.post("/upload")
    @login_required
    def upload():
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Choose a file first.", "error")
            return redirect(url_for("analyze"))
        try:
            sha, created = ingest(f.read(), f.filename, "web")
        except BadUpload as e:
            flash(str(e), "error")
            return redirect(url_for("analyze"))
        if not created:
            flash("This file was analysed before; showing the existing report.", "info")
        return redirect(url_for("report", sha=sha))

    @app.get("/search")
    @login_required
    def search():
        q = request.args.get("q", "").strip()
        if not q:
            return redirect(url_for("submissions"))
        rows = find(q)
        if len(rows) == 1:
            return redirect(url_for("report", sha=rows[0]["sha256"]))
        return render_template("search.html", q=q, rows=[summarize(r) for r in rows])

    # ---------- report ----------
    @app.get("/file/<sha>")
    @login_required
    def report(sha: str):
        rep = full_report(sha.lower()) or abort(404)
        return render_template("report.html", r=rep, print_mode=False)

    @app.get("/file/<sha>/print")
    @login_required
    def report_print(sha: str):
        rep = full_report(sha.lower()) or abort(404)
        return render_template("report.html", r=rep, print_mode=True)

    @app.get("/file/<sha>/json")
    @login_required
    def report_json(sha: str):
        rep = full_report(sha.lower()) or abort(404)
        return Response(json.dumps(rep, indent=2, default=str), mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename=sa2_{sha[:12]}.json"})

    @app.get("/file/<sha>/status")
    @login_required
    def report_status(sha: str):
        f = db.one("SELECT status FROM files WHERE sha256=?", (sha.lower(),)) or abort(404)
        return jsonify(f)

    @app.post("/file/<sha>/disposition")
    @login_required
    def set_disposition(sha: str):
        d = request.form.get("disposition", "")
        if d not in DISPOSITIONS:
            abort(400)
        db.x("UPDATE files SET disposition=?, disposition_note=?, disposition_at=? WHERE sha256=?",
             (d, request.form.get("note", "")[:500], now() if d else None, sha.lower()))
        flash(f"Disposition set to {DISPOSITIONS[d]}.", "ok")
        return redirect(request.referrer or url_for("report", sha=sha))

    @app.post("/file/<sha>/delete")
    @login_required
    def delete_file(sha: str):
        """Remove a file from the database: its record, submissions, quarantined copy and Binary Ninja cache."""
        sha = sha.lower()
        if not db.one("SELECT 1 FROM files WHERE sha256=?", (sha,)):
            abort(404)
        db.x("DELETE FROM submissions WHERE sha256=?", (sha,))
        db.x("DELETE FROM files WHERE sha256=?", (sha,))
        from src.v8 import bn_live
        for p in [qdir / sha, *bn_live.CACHE_DIR.glob(f"*/{sha}.json")]:
            try:
                os.chmod(p, stat.S_IWRITE)  # quarantined files are read-only
                p.unlink()
            except OSError:
                pass
        flash(f"Deleted {sha[:12]}… from the database. Submitting the file again scans it afresh.", "ok")
        return redirect(url_for("submissions"))

    @app.post("/file/<sha>/reanalyse")
    @login_required
    def reanalyse(sha: str):
        if db.x("UPDATE files SET status='queued' WHERE sha256=?", (sha.lower(),)):
            jobs.put(sha.lower())
        return redirect(url_for("report", sha=sha))

    def csv_rows(shas: list[str]) -> list[dict[str, Any]]:
        rows = []
        for sha in shas:
            r = full_report(sha)
            eng = {e["name"]: e for e in r.get("engines") or [] if isinstance(e, dict) and e.get("name")}
            dp = r.get("decision_path") or {}
            sig = (r.get("pe") or {}).get("signature")
            a = r.get("assessment") or {}
            top = ((r.get("explanation") or {}).get("top") or [{}])[0]
            rows.append({
                "sha256": r["sha256"], "md5": r["md5"], "sha1": r["sha1"], "imphash": r.get("imphash"),
                "size": r["size"], "names": ";".join(r["names"]), "status": r["status"], "verdict": r["verdict"],
                "risk": r["risk"], "assessment": a.get("label"), "disposition": DISPOSITIONS.get(r.get("disposition") or "", ""),
                "flag_count": r.get("flag_count"), "engine_count": r.get("engine_count"),
                "decision_path": dp.get("path") or ("legacy_v3.2" if r["view"]["legacy"] else None),
                "fallback_reason": (eng.get(scanner.ENGINE_BLEND) or {}).get("fallback_reason"),
                "engines_disagree": r["view"]["disagree"],
                "top_reason": top.get("title"), "top_reason_contribution": top.get("contribution"),
                "signals": ";".join(s["title"] for s in r.get("all_signals", [])),
                "signature": sig.get("status") if isinstance(sig, dict) else sig,
                "signer": sig.get("signer") if isinstance(sig, dict) else "",
                **{f"{n}_{k}": e.get(src) for n, e in eng.items()
                   for k, src in (("score", "probability"), ("threshold", "threshold"), ("flagged", "flagged"))},
                **{k: (eng.get(scanner.ENGINE_BLEND) or {}).get(k) for k in ("blend_margin", "bn_score") if scanner.ENGINE_BLEND in eng},
                "first_seen": r["first_seen"], "last_seen": r["last_seen"], "submissions": len(r["submissions"]),
                "sources": ";".join(sorted({s["source"] for s in r["submissions"]})), "scan_ms": r.get("scan_ms"),
            })
        return rows

    def csv_response(rows: list[dict[str, Any]], name: str) -> Response:
        buf = io.StringIO()
        if rows:
            fields = list(dict.fromkeys(k for r in rows for k in r))  # engines can differ between rows (old reports)
            w = csv.DictWriter(buf, fieldnames=fields)
            w.writeheader()
            w.writerows([{k: csv_safe(v) for k, v in r.items()} for r in rows])
        return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={name}"})

    @app.get("/file/<sha>/csv")
    @login_required
    def report_csv(sha: str):
        if not db.one("SELECT 1 FROM files WHERE sha256=?", (sha.lower(),)):
            abort(404)
        return csv_response(csv_rows([sha.lower()]), f"sa2_{sha[:12]}.csv")

    # ---------- submissions ----------
    def filtered() -> list[dict[str, Any]]:
        a, where, args = request.args, [], []
        v = a.get("verdict", "")
        if v == "borderline":
            where.append("f.verdict='benign' AND f.probability >= ? AND f.probability < ?")
            args += [border, thr]
        elif v in ("malicious", "benign"):
            where.append("f.verdict=?")
            args.append(v)
        elif v in ("error", "queued", "scanning"):
            where.append("f.status=?")
            args.append(v)
        d = a.get("disposition", "")
        if d == "unreviewed" or (d and d in DISPOSITIONS):
            where.append("COALESCE(f.disposition,'')=?")
            args.append("" if d == "unreviewed" else d)
        if a.get("source"):
            where.append("f.sha256 IN (SELECT sha256 FROM submissions WHERE source=?)")
            args.append(a["source"])
        if a.get("sensor"):
            where.append("f.sha256 IN (SELECT sha256 FROM submissions WHERE sensor_id=?)")
            args.append(a["sensor"])
        if a.get("q"):
            where.append("(f.sha256 LIKE ? OR f.md5 LIKE ? OR f.sha1 LIKE ? OR f.name LIKE ? OR f.imphash=?)")
            like = f"%{a['q'].strip()}%"
            args += [like, like, like, like, a["q"].strip()]
        if a.get("from"):
            where.append("f.last_seen >= ?")
            args.append(a["from"])
        if a.get("to"):
            where.append("f.first_seen <= ?")
            args.append(a["to"] + "T23:59:59")
        sql = "SELECT f.*, (SELECT COUNT(*) FROM submissions s WHERE s.sha256=f.sha256) n_sub, " \
              "(SELECT GROUP_CONCAT(DISTINCT source) FROM submissions s WHERE s.sha256=f.sha256) sources FROM files f"
        if where:
            sql += " WHERE " + " AND ".join(where)
        order = {"score": "f.probability DESC", "name": "f.name COLLATE NOCASE", "seen": "f.last_seen DESC"}.get(a.get("sort", ""), "f.last_seen DESC")
        return db.q(sql + f" ORDER BY {order}", args)

    @app.get("/submissions")
    @login_required
    def submissions():
        rows = filtered()
        fmt = request.args.get("export")
        if fmt == "csv":
            return csv_response(csv_rows([r["sha256"] for r in rows]), "sa2_submissions.csv")
        if fmt == "json":
            data = [full_report(r["sha256"]) for r in rows]
            return Response(json.dumps(data, indent=2, default=str), mimetype="application/json",
                            headers={"Content-Disposition": "attachment; filename=sa2_submissions.json"})
        page = max(int(request.args.get("page", 1) or 1), 1)
        pages = max((len(rows) + 24) // 25, 1)
        page = min(page, pages)
        args = {k: v for k, v in request.args.items() if k != "page"}
        return render_template("submissions.html", rows=[summarize(r) for r in rows[(page - 1) * 25: page * 25]],
                               total=len(rows), page=page, pages=pages, args=args,
                               sensors=[s["sensor_id"] for s in db.q("SELECT sensor_id FROM sensors")])

    # ---------- insights ----------
    @app.get("/insights")
    @login_required
    def insights():
        only = request.args.get("only", "all")
        done = db.q("SELECT * FROM files WHERE status='done'")
        rows = [f for f in done if only != "flagged" or f["verdict"] == "malicious"]
        per_dll: dict[str, Counter] = {}
        files_per_dll: Counter = Counter()
        sig_by_verdict: dict[str, Counter] = defaultdict(Counter)
        sig_meta: dict[str, dict] = {}
        feat_push: dict[str, list[float]] = defaultdict(list)
        feat_title: dict[str, str] = {}
        for f in done:
            rep = json.loads(f["report_json"] or "{}")
            for s in rep.get("signals") or []:
                key = s["id"]
                sig_by_verdict[key][f["verdict"]] += 1
                sig_meta.setdefault(key, {**s, "title": explain.generic_title(s)})
            if f["verdict"] == "malicious":
                for r in (rep.get("explanation") or {}).get("top", []):
                    if r["contribution"] > 0:
                        feat_push[r["title"]].append(r["contribution"])
        for f in rows:
            imps = (json.loads(f["report_json"] or "{}").get("pe") or {}).get("imports", {})
            for dll, fns in imps.items():
                files_per_dll[dll] += 1
                per_dll.setdefault(dll, Counter()).update(set(fns))
        cols = [(dll, n, per_dll[dll].most_common(8)) for dll, n in files_per_dll.most_common(6)]
        sigs = sorted(((sig_meta[k], c) for k, c in sig_by_verdict.items()), key=lambda x: -sum(x[1].values()))
        feats = sorted(((t, len(v), sum(v) / len(v)) for t, v in feat_push.items()), key=lambda x: -x[1] * x[2])[:10]
        n_mal = sum(1 for f in done if f["verdict"] == "malicious")
        ref = explain.reference() or {}
        classes = [(k, c) for k, c in (ref.get("classes") or {}).items()
                   if isinstance(c, dict) and isinstance(c.get("benign"), (int, float)) and isinstance(c.get("malicious"), (int, float))]
        return render_template("insights.html", cols=cols, only=only, n=len(rows), sigs=sigs, feats=feats,
                               n_done=len(done), n_mal=n_mal, ref=ref, classes=classes,
                               ref_path=Path(str(getattr(explain, "REFERENCE", ""))).as_posix())

    # ---------- sensors ----------
    @app.route("/sensors", methods=["GET", "POST"])
    @login_required
    def sensors():
        if request.method == "POST" and request.form.get("action") == "rotate":
            db.set_setting("api_key", secrets.token_urlsafe(24))
            flash("API key rotated. Paste the new key into every EDR sensor's Settings page.", "ok")
            return redirect(url_for("sensors"))
        return render_template("sensors.html", sensors=sensors_with_health(), api_key=db.setting("api_key"),
                               base=request.host_url.rstrip("/"))

    @app.get("/sensors/<sid>")
    @login_required
    def sensor(sid: str):
        s = next((x for x in sensors_with_health() if x["sensor_id"] == sid), None) or abort(404)
        hist = db.q("SELECT at, stats_json FROM sensor_stats WHERE sensor_id=? ORDER BY at", (sid,))
        series = {k: [] for k in ("processes_observed", "connections_observed", "uploads_sent", "alerts_created")}
        for h in hist[-240:]:
            st = json.loads(h["stats_json"] or "{}").get("totals", {})
            for k in series:
                series[k].append(st.get(k, 0))
        files = [summarize(f) for f in db.q(
            "SELECT f.* FROM files f WHERE f.sha256 IN (SELECT sha256 FROM submissions WHERE sensor_id=?) ORDER BY f.last_seen DESC LIMIT 50", (sid,))]
        return render_template("sensor.html", s=s, series=series, files=files, n_hist=len(hist))

    # ---------- model / settings / glossary ----------
    @app.get("/model")
    @login_required
    def model():
        fs = freeze_status()
        ref = explain.reference() or {}
        ops = ref.get("r1_operating_points") if isinstance(ref.get("r1_operating_points"), dict) else {}
        nsis = (ref.get("classes") or {}).get("nsis")
        return render_template("model.html", thrs=scanner.thresholds(), bad=fs["bad"], models_ok=fs["models_ok"], ev=evidence(),
                               params=frozen_params(), ops=ops, nsis=nsis if isinstance(nsis, dict) else None,
                               scale_note=scanner.SCALE_NOTE)

    @app.route("/settings", methods=["GET", "POST"])
    @login_required
    def settings():
        if request.method == "POST" and request.form.get("action") == "rescan":
            n = 0
            for r in db.q("SELECT sha256 FROM files"):
                db.x("UPDATE files SET status='queued' WHERE sha256=?", (r["sha256"],))
                jobs.put(r["sha256"])
                n += 1
            flash(f"Queued {n} file(s) for re-analysis.", "ok")
            return redirect(url_for("settings"))
        return render_template("settings.html", api_key=db.setting("api_key"), base=request.host_url.rstrip("/"),
                               env_pw=bool(os.environ.get("SA2_ADMIN_PASSWORD")), data_dir=str(data_dir), bn=bn_status())

    def bn_status() -> dict[str, Any]:
        """Binary Ninja configuration in effect, and whether its MCP endpoint answers now (short probe)."""
        from src.v8 import bn_live
        cfg = bn_live.settings()
        out = {**cfg, "reachable": None, "windows": os.name == "nt", "probe_error": None}
        if cfg["enabled"]:
            try:
                out["reachable"] = bool(bn_live.probe(cfg["url"], min(cfg["probe_timeout"], 2.0)))
            except Exception as e:
                out["reachable"], out["probe_error"] = False, type(e).__name__
        return out

    @app.get("/glossary")
    @login_required
    def glossary():
        return render_template("glossary.html", api_groups=explain.API_GROUPS, packers=explain.PACKERS, extra=explain.GLOSSARY_EXTRA)

    # ---------- API (machine clients, X-API-Key) ----------
    @app.get("/api/v1/ping")
    @require_key
    def api_ping():
        t = scanner.thresholds()
        return jsonify(ok=True, server="SA2 Scan", model_tag=scanner.MODEL_TAG, decision_engine=scanner.ENGINE_BLEND,
                       thresholds={k: v["threshold"] for k, v in t.items()}, time=now())

    @app.post("/api/v1/sensors/heartbeat")
    @require_key
    def api_heartbeat():
        body = request.get_json(silent=True) or {}
        sid = str(body.get("sensor_id") or "")[:128]
        if not sid:
            return jsonify(error="sensor_id required"), 400
        t, stats = now(), json.dumps(body.get("stats") or {})
        db.x("INSERT INTO sensors(sensor_id, hostname, agent_version, first_seen, last_heartbeat, stats_json) VALUES(?,?,?,?,?,?) "
             "ON CONFLICT(sensor_id) DO UPDATE SET hostname=excluded.hostname, agent_version=excluded.agent_version, "
             "last_heartbeat=excluded.last_heartbeat, stats_json=excluded.stats_json",
             (sid, str(body.get("hostname", ""))[:128], str(body.get("agent_version", ""))[:32], t, t, stats))
        db.x("INSERT INTO sensor_stats(sensor_id, at, stats_json) VALUES(?,?,?)", (sid, t, stats))
        db.x("DELETE FROM sensor_stats WHERE at < ?", ((datetime.now(timezone.utc) - timedelta(days=7)).isoformat(timespec="seconds"),))
        return jsonify(ok=True, time=t)

    @app.get("/api/v1/files/<sha>")
    @require_key
    def api_get(sha: str):
        rep = full_report(sha.lower())
        return (jsonify(rep), 200) if rep else (jsonify(error="not found"), 404)

    @app.post("/api/v1/files")
    @require_key
    def api_upload():
        f = request.files.get("file")
        if not f:
            return jsonify(error="multipart field 'file' required"), 400
        try:
            meta = json.loads(request.form.get("meta") or "{}")
        except json.JSONDecodeError:
            return jsonify(error="meta must be JSON"), 400
        try:
            sha, created = ingest(f.read(), f.filename, str(meta.get("source") or "api")[:16],
                                  str(meta.get("sensor_id") or "")[:128] or None, meta)
        except BadUpload as e:
            return jsonify(error=str(e)), e.code
        return jsonify(sha256=sha, status="queued" if created else "known"), 202

    @app.errorhandler(413)
    def too_big(_):
        if request.path.startswith("/api/"):
            return jsonify(error="File larger than 50 MB"), 413
        flash("File larger than 50 MB.", "error")
        return redirect(url_for("analyze"))

    @app.errorhandler(404)
    def not_found(_):
        if request.path.startswith("/api/"):
            return jsonify(error="not found"), 404
        return render_template("error.html", code=404, msg="Nothing here. The file or page does not exist."), 404

    if start_worker:
        # re-scan anything still queued, and reports produced by an older report format (adds explanations)
        for r in db.q("SELECT sha256, status, report_json FROM files"):
            old = r["status"] in ("done", "error") and json.loads(r["report_json"] or "{}").get("report_version", 1) < scanner.REPORT_VERSION
            if r["status"] in ("queued", "scanning") or old:
                jobs.put(r["sha256"])
        threading.Thread(target=worker, daemon=True, name="scan-worker").start()
    return app


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SA2 Scan dashboard")
    ap.add_argument("--host", default="127.0.0.1", help="Bind address (use 0.0.0.0 only on a trusted lab network)")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)
    os.chdir(ROOT)  # some research modules use repo-relative paths
    from src.v8 import bn_live, deploy
    try:
        if bn_live.restore_settings():
            print("  Restored your Binary Ninja settings.json (an earlier scan was interrupted).")
    except OSError as e:
        print(f"  Warning: could not restore Binary Ninja settings ({e}). Backup: %APPDATA%\\Binary Ninja\\{bn_live.SETTINGS_BACKUP}")
    try:
        import thrember  # noqa: F401  (EMBER2024 feature extractor)
    except ImportError:
        print("  [error] Python package 'thrember' is missing. Run: .venv\\Scripts\\python.exe -m pip install -r requirements.txt",
              file=sys.stderr)
        return 2
    try:
        scanner.bundle()  # load models before serving; downloads EMBER2024_PE.model on first use
    except deploy.ModelMissing as e:
        print(f"  [error] EMBER2024 model not available ({e.kind.replace('_', ' ')}): {e}", file=sys.stderr)
        return 2
    except SystemExit as e:  # freeze verification or bundle consistency failure
        print(f"  [error] Could not load the frozen V8 bundle: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"  [error] Missing model file: {e.filename}. These files are tracked in git; run 'git pull'.", file=sys.stderr)
        return 2
    app = create_app()
    db: DB = app.config["DB"]
    pw = "(from SA2_ADMIN_PASSWORD)" if os.environ.get("SA2_ADMIN_PASSWORD") else db.setting("admin_password")
    bn = bn_live.settings()
    print(f"\n  SA2 Scan       http://{args.host}:{args.port}/")
    print(f"  Sign in with   password: {pw}")
    print(f"  EDR API key    {db.setting('api_key')}")
    print(f"  Model          V8 blend, threshold {app.config['THRESHOLD']:.4f} (EMBER2024-only when Binary Ninja features are unavailable)")
    if not bn["enabled"]:
        print("  Binary Ninja   disabled (SA2_BN=0): every verdict is EMBER2024 alone")
    else:
        print(f"  Binary Ninja   used when its MCP server answers at {bn['url']}")
        if bn["mode_switch"] == "restart" and os.name == "nt":
            print("  WARNING        each scan that needs Binary Ninja force-closes and restarts it (minutes per file). "
                  "Save your work in Binary Ninja, or set SA2_BN_MODE_SWITCH=off or SA2_BN=0.")
    print("", flush=True)
    app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
