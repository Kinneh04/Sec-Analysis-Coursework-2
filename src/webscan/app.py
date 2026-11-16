"""SA2 Scan: VT-style uploader + admin panel over the frozen V3.2 models (static analysis only).

  .venv\\Scripts\\python.exe -m src.webscan.app --port 8000
"""

from __future__ import annotations

import argparse
import csv
import hmac
import io
import json
import os
import queue
import re
import secrets
import stat
import statistics
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any

from flask import (Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for)

from src.common.sqlite_db import DB
from src.webscan import scanner

ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 50 * 1024 * 1024
ONLINE_SECONDS = 90
SCHEMA = """
CREATE TABLE IF NOT EXISTS files(sha256 TEXT PRIMARY KEY, md5 TEXT, sha1 TEXT, imphash TEXT, size INTEGER, name TEXT,
  first_seen TEXT, last_seen TEXT, status TEXT, verdict TEXT, probability REAL, scan_ms INTEGER, report_json TEXT);
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


class BadUpload(Exception):
    def __init__(self, msg: str, code: int):
        super().__init__(msg)
        self.code = code


def create_app(data_dir: Path | None = None, *, start_worker: bool = True, scan_fn=None) -> Flask:
    data_dir = Path(data_dir or ROOT / "artifacts" / "dashboard")
    qdir = data_dir / "quarantine"
    qdir.mkdir(parents=True, exist_ok=True)
    db = DB(data_dir / "scan.db", SCHEMA)
    scan_fn = scan_fn or scanner.scan

    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=MAX_BYTES + 1024 * 1024, SESSION_COOKIE_SAMESITE="Lax", DB=db)
    if not db.setting("secret_key"):
        db.set_setting("secret_key", secrets.token_hex(32))
    if not db.setting("api_key"):
        db.set_setting("api_key", secrets.token_urlsafe(24))
    if not db.setting("admin_password"):
        db.set_setting("admin_password", secrets.token_urlsafe(9))
    app.secret_key = db.setting("secret_key")
    jobs: queue.Queue[str] = queue.Queue()

    # ---------- core ----------
    def process(sha: str) -> None:
        db.x("UPDATE files SET status='scanning' WHERE sha256=?", (sha,))
        try:
            rep = scan_fn(qdir / sha)
        except Exception as e:  # keep the worker alive on any parser/model failure
            rep = {"verdict": "error", "error": f"{type(e).__name__}: {e}", "engines": [], "top_features": [], "pe": {}}
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
            raise BadUpload("Not a PE file (no MZ header). SA2 models only analyse Windows PE files.", 415)
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
        return {**f, **rep, "status": f["status"], "verdict": f["verdict"],
                "names": sorted({s["filename"] for s in subs if s["filename"]}), "submissions": subs}

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

    def require_admin(fn):
        @wraps(fn)
        def inner(*a, **kw):
            if not session.get("admin"):
                return redirect(url_for("admin_login", next=request.path))
            return fn(*a, **kw)
        return inner

    # a Jinja global (not a context var) so imported macros such as badge() can read it
    app.jinja_env.globals["thr"] = scanner.thresholds()["pe_v3"]["threshold"]

    @app.context_processor
    def ctx():
        return {"is_admin": bool(session.get("admin"))}

    @app.template_filter("fromjson")
    def fromjson(s):
        return json.loads(s or "{}")

    # ---------- public ----------
    @app.get("/")
    def home():
        return render_template("home.html")

    @app.post("/upload")
    def upload():
        f = request.files.get("file")
        if not f:
            flash("Choose a file first.")
            return redirect(url_for("home"))
        try:
            sha, _ = ingest(f.read(), f.filename, "web")
        except BadUpload as e:
            flash(str(e))
            return redirect(url_for("home"))
        return redirect(url_for("report", sha=sha))

    @app.get("/search")
    def search():
        q = request.args.get("q", "").strip()
        if not q:
            return redirect(url_for("home"))
        rows = find(q)
        if len(rows) == 1:
            return redirect(url_for("report", sha=rows[0]["sha256"]))
        return render_template("search.html", q=q, rows=rows)

    @app.get("/file/<sha>")
    def report(sha: str):
        rep = full_report(sha.lower())
        if not rep:
            abort(404)
        return render_template("report.html", r=rep, print_mode=False)

    @app.get("/file/<sha>/print")
    def report_print(sha: str):
        rep = full_report(sha.lower()) or abort(404)
        return render_template("report.html", r=rep, print_mode=True)

    @app.get("/file/<sha>/json")
    def report_json(sha: str):
        rep = full_report(sha.lower()) or abort(404)
        return Response(json.dumps(rep, indent=2, default=str), mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename=sa2_{sha[:12]}.json"})

    @app.get("/file/<sha>/status")
    def report_status(sha: str):
        f = db.one("SELECT status FROM files WHERE sha256=?", (sha.lower(),)) or abort(404)
        return jsonify(f)

    def csv_rows(shas: list[str]) -> list[dict[str, Any]]:
        rows = []
        for sha in shas:
            r = full_report(sha)
            eng = {e["name"]: e for e in r.get("engines", [])}
            rows.append({
                "sha256": r["sha256"], "md5": r["md5"], "sha1": r["sha1"], "imphash": r.get("imphash"),
                "size": r["size"], "names": ";".join(r["names"]), "status": r["status"], "verdict": r["verdict"],
                "flag_count": r.get("flag_count"), "engine_count": r.get("engine_count"),
                **{f"{n}_{k}": eng.get(n, {}).get(k) for n in ("pe_v3", "pe_v1s") for k in ("probability", "threshold", "flagged")},
                "signature": (r.get("pe") or {}).get("signature"), "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                "submissions": len(r["submissions"]), "sources": ";".join(sorted({s["source"] for s in r["submissions"]})),
                "scan_ms": r.get("scan_ms"),
            })
        return rows

    def csv_response(rows: list[dict[str, Any]], name: str) -> Response:
        buf = io.StringIO()
        if rows:
            w = csv.DictWriter(buf, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={name}"})

    @app.get("/file/<sha>/csv")
    def report_csv(sha: str):
        if not db.one("SELECT 1 FROM files WHERE sha256=?", (sha.lower(),)):
            abort(404)
        return csv_response(csv_rows([sha.lower()]), f"sa2_{sha[:12]}.csv")

    @app.get("/api")
    def api_doc():
        return render_template("api.html")

    # ---------- API ----------
    @app.get("/api/v1/ping")
    @require_key
    def api_ping():
        thr = scanner.thresholds()
        return jsonify(ok=True, server="SA2 Scan", model_tag=scanner.MODEL_TAG,
                       thresholds={k: v["threshold"] for k, v in thr.items()}, time=now())

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

    # ---------- admin ----------
    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if request.method == "POST":
            if hmac.compare_digest(request.form.get("password", ""), os.environ.get("SA2_ADMIN_PASSWORD") or db.setting("admin_password")):
                session["admin"] = True
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/admin") else url_for("admin_hud"))
            flash("Wrong password.")
        return render_template("admin_login.html")

    @app.get("/admin/logout")
    def admin_logout():
        session.clear()
        return redirect(url_for("home"))

    def sensors_with_health() -> list[dict[str, Any]]:
        rows = db.q("SELECT * FROM sensors ORDER BY last_heartbeat DESC")
        for s in rows:
            s["online"] = age_seconds(s["last_heartbeat"]) <= ONLINE_SECONDS
            s["stats"] = json.loads(s.pop("stats_json") or "{}")
        return rows

    @app.get("/admin")
    @require_admin
    def admin_hud():
        done = db.q("SELECT probability, scan_ms, verdict, report_json FROM files WHERE status='done'")
        ms = [d["scan_ms"] for d in done if d["scan_ms"] is not None]
        sensors = sensors_with_health()
        kpi = {
            "total": db.val("SELECT COUNT(*) FROM files"),
            "flagged": db.val("SELECT COUNT(*) FROM files WHERE verdict='malicious'"),
            "benign": db.val("SELECT COUNT(*) FROM files WHERE verdict='benign'"),
            "queued": db.val("SELECT COUNT(*) FROM files WHERE status IN ('queued','scanning')"),
            "errors": db.val("SELECT COUNT(*) FROM files WHERE status='error'"),
            "sensors_online": sum(s["online"] for s in sensors),
            "median_ms": round(statistics.median(ms)) if ms else None,
        }
        bins = [0] * 20
        for d in done:
            if d["probability"] is not None:
                bins[min(int(d["probability"] * 20), 19)] += 1
        days = [(datetime.now(timezone.utc) - timedelta(days=i)).date().isoformat() for i in range(13, -1, -1)]
        per_day = {d: Counter() for d in days}
        for r in db.q("SELECT substr(s.at,1,10) day, COALESCE(f.verdict, f.status) v, COUNT(*) n FROM submissions s "
                      "JOIN files f ON f.sha256=s.sha256 WHERE s.at >= ? GROUP BY day, v", (days[0],)):
            if r["day"] in per_day:
                per_day[r["day"]][r["v"]] += r["n"]
        sources = db.q("SELECT source, COUNT(*) n FROM submissions GROUP BY source ORDER BY n DESC")
        # ponytail: parses every report JSON per HUD load; fine for coursework scale, add an imports table if slow
        dll_count: Counter = Counter()
        for d in done:
            dll_count.update((json.loads(d["report_json"] or "{}").get("pe") or {}).get("imports", {}).keys())
        recent = db.q("SELECT s.at, s.source, s.sensor_id, s.filename, f.sha256, f.status, f.verdict, f.probability "
                      "FROM submissions s JOIN files f ON f.sha256=s.sha256 ORDER BY s.id DESC LIMIT 12")
        return render_template("admin_hud.html", kpi=kpi, bins=bins, per_day=per_day, sources=sources,
                               day_max=max([sum(c.values()) for c in per_day.values()] + [1]),
                               dlls=dll_count.most_common(10), n_done=len(done), recent=recent, sensors=sensors[:5])

    def filtered() -> list[dict[str, Any]]:
        a, where, args = request.args, [], []
        for col in ("verdict", "status"):
            if a.get(col):
                where.append(f"f.{col}=?")
                args.append(a[col])
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
        for key, op in (("min", ">="), ("max", "<=")):
            try:
                v = float(a.get(key, ""))
                where.append(f"f.probability {op} ?")
                args.append(v)
            except ValueError:
                pass
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
        return db.q(sql + " ORDER BY f.last_seen DESC", args)

    @app.get("/admin/submissions")
    @require_admin
    def admin_submissions():
        rows = filtered()
        fmt = request.args.get("export")
        if fmt == "csv":
            return csv_response(csv_rows([r["sha256"] for r in rows]), "sa2_submissions.csv")
        if fmt == "json":
            data = [full_report(r["sha256"]) for r in rows]
            return Response(json.dumps(data, indent=2, default=str), mimetype="application/json",
                            headers={"Content-Disposition": "attachment; filename=sa2_submissions.json"})
        page = max(int(request.args.get("page", 1) or 1), 1)
        pages = max((len(rows) + 49) // 50, 1)
        args = {k: v for k, v in request.args.items() if k != "page"}
        return render_template("admin_submissions.html", rows=rows[(page - 1) * 50: page * 50], total=len(rows),
                               page=min(page, pages), pages=pages, args=args,
                               sensors=[s["sensor_id"] for s in db.q("SELECT sensor_id FROM sensors")])

    @app.post("/admin/reanalyse/<sha>")
    @require_admin
    def admin_reanalyse(sha: str):
        if db.x("UPDATE files SET status='queued' WHERE sha256=?", (sha.lower(),)):
            jobs.put(sha.lower())
        return redirect(url_for("report", sha=sha))

    @app.get("/admin/matrix")
    @require_admin
    def admin_matrix():
        only = request.args.get("only", "all")
        sql = "SELECT sha256, report_json FROM files WHERE status='done'" + (" AND verdict='malicious'" if only == "flagged" else "")
        per_dll: dict[str, Counter] = {}
        files_per_dll: Counter = Counter()
        rows = db.q(sql)
        for r in rows:
            imps = (json.loads(r["report_json"] or "{}").get("pe") or {}).get("imports", {})
            for dll, fns in imps.items():
                files_per_dll[dll] += 1
                per_dll.setdefault(dll, Counter()).update(set(fns))
        cols = [(dll, n, per_dll[dll].most_common(8)) for dll, n in files_per_dll.most_common(6)]
        return render_template("admin_matrix.html", cols=cols, only=only, n=len(rows))

    @app.route("/admin/sensors", methods=["GET", "POST"])
    @require_admin
    def admin_sensors():
        if request.method == "POST" and request.form.get("action") == "rotate":
            db.set_setting("api_key", secrets.token_urlsafe(24))
            flash("API key rotated. Update it on every EDR Settings page.")
            return redirect(url_for("admin_sensors"))
        return render_template("admin_sensors.html", sensors=sensors_with_health(), api_key=db.setting("api_key"),
                               base=request.host_url.rstrip("/"))

    @app.get("/admin/sensors/<sid>")
    @require_admin
    def admin_sensor(sid: str):
        s = next((x for x in sensors_with_health() if x["sensor_id"] == sid), None) or abort(404)
        hist = db.q("SELECT at, stats_json FROM sensor_stats WHERE sensor_id=? ORDER BY at", (sid,))
        series = {k: [] for k in ("processes_observed", "connections_observed", "uploads_sent", "alerts_created")}
        for h in hist[-240:]:
            st = json.loads(h["stats_json"] or "{}").get("totals", {})
            for k in series:
                series[k].append(st.get(k, 0))
        files = db.q("SELECT f.sha256, f.name, f.verdict, f.probability, MAX(s.at) at FROM submissions s JOIN files f "
                     "ON f.sha256=s.sha256 WHERE s.sensor_id=? GROUP BY f.sha256 ORDER BY at DESC LIMIT 50", (sid,))
        return render_template("admin_sensor.html", s=s, series=series, files=files, n_hist=len(hist))

    @app.get("/admin/model")
    @require_admin
    def admin_model():
        from src.v3 import freeze
        bad = freeze.verify(tag=scanner.MODEL_TAG)
        blind_path = Path("artifacts/v3.2/blind/blind_results.json")
        blind = json.loads(blind_path.read_text(encoding="utf-8")) if blind_path.is_file() else {}
        return render_template("admin_model.html", thrs=scanner.thresholds(), bad=bad, blind=blind,
                               cal=json.loads(scanner.CALIBRATION.read_text(encoding="utf-8")))

    @app.errorhandler(413)
    def too_big(_):
        if request.path.startswith("/api/"):
            return jsonify(error="File larger than 50 MB"), 413
        flash("File larger than 50 MB.")
        return redirect(url_for("home"))

    if start_worker:
        for r in db.q("SELECT sha256 FROM files WHERE status IN ('queued','scanning')"):
            jobs.put(r["sha256"])
        threading.Thread(target=worker, daemon=True, name="scan-worker").start()
    return app


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SA2 Scan dashboard")
    ap.add_argument("--host", default="127.0.0.1", help="Bind address (use 0.0.0.0 only on a trusted lab network)")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)
    os.chdir(ROOT)  # model/freeze paths in src.v3 are repo-relative
    scanner.bundle()  # load models before serving; fail fast if artifacts are missing
    app = create_app()
    db: DB = app.config["DB"]
    pw = "(from SA2_ADMIN_PASSWORD)" if os.environ.get("SA2_ADMIN_PASSWORD") else db.setting("admin_password")
    print(f"\n  SA2 Scan       http://{args.host}:{args.port}/")
    print(f"  Admin panel    http://{args.host}:{args.port}/admin   password: {pw}")
    print(f"  EDR API key    {db.setting('api_key')}\n")
    app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
