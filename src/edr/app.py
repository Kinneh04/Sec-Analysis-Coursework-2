"""SA2 Sentinel: on-machine EDR agent + Carbon-Black-style console (localhost only).

  .venv\\Scripts\\python.exe -m src.edr.app --port 8001
"""

from __future__ import annotations

import argparse
import csv
import hmac
import secrets
import io
import json
import os
from pathlib import Path

from flask import Flask, Response, abort, flash, redirect, render_template, request, session, url_for

from src.edr import rules
from src.edr.core import AGENT_VERSION, ALERT_STATUSES, Agent, now

ROOT = Path(__file__).resolve().parents[2]
SERIES_KEYS = ["processes_observed", "connections_observed", "uploads_sent", "alerts_created"]


def create_app(data_dir: Path | None = None, *, start_agent: bool = True) -> Flask:
    agent = Agent(Path(data_dir or ROOT / "artifacts" / "edr"))
    db = agent.db
    app = Flask(__name__)
    if not db.setting("secret_key"):
        db.set_setting("secret_key", os.urandom(24).hex())
    app.secret_key = db.setting("secret_key")
    app.config.update(AGENT=agent, SESSION_COOKIE_SAMESITE="Strict")

    @app.before_request
    def guard():
        # Localhost-only console: block DNS-rebinding hosts and cross-site form posts (CSRF token in a Strict cookie).
        if request.host.rsplit(":", 1)[0] not in ("127.0.0.1", "localhost"):
            abort(403)
        session.setdefault("csrf", secrets.token_urlsafe(16))
        if request.method == "POST" and not hmac.compare_digest(request.form.get("csrf", ""), session["csrf"]):
            abort(400, "CSRF token missing or wrong; reload the page.")

    @app.context_processor
    def ctx():
        cfg = agent.cfg()
        return {"csrf": session.get("csrf", ""), "conn": agent.conn, "cfg": cfg, "elevated": agent.elevated, "version": AGENT_VERSION,
                "report_url": lambda sha: f"{cfg['dashboard_url'].rstrip('/')}/file/{sha}"}

    @app.get("/")
    def hud():
        st = agent.stats()
        alerts = db.q("SELECT * FROM alerts WHERE status IN ('Unresolved','In Progress') ORDER BY created DESC LIMIT 10")
        talkers = db.q("SELECT process, COUNT(DISTINCT rip) n FROM connections WHERE process IS NOT NULL "
                       "GROUP BY process ORDER BY n DESC LIMIT 8")
        recent = db.q("SELECT * FROM binaries ORDER BY last_seen DESC LIMIT 8")
        return render_template("hud.html", st=st, alerts=alerts, talkers=talkers, recent=recent,
                               series=agent.series(SERIES_KEYS[:2] + ["alerts_created"], 60))

    @app.route("/alerts", methods=["GET", "POST"])
    def alerts():
        if request.method == "POST":
            status = request.form.get("status")
            ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
            if status in ALERT_STATUSES and ids:
                t = now()
                closed = status in ("Resolved", "False Positive")
                for i in ids:
                    db.x("UPDATE alerts SET status=?, updated=?, resolved=?, note=CASE WHEN ? THEN 'analyst' ELSE note END WHERE id=?",
                         (status, t, t if closed else None, int(closed), i))
                flash(f"{len(ids)} alert(s) marked {status}.")
            return redirect(request.referrer or url_for("alerts"))
        st = request.args.get("status", "")
        q = request.args.get("q", "").strip()
        sql, args = "SELECT * FROM alerts WHERE 1=1", []
        if st:
            sql += " AND status=?"
            args.append(st)
        if q:
            sql += " AND (sha256 LIKE ? OR path LIKE ? OR cause LIKE ?)"
            args += [f"%{q}%"] * 3
        return render_template("alerts.html", rows=db.q(sql + " ORDER BY created DESC LIMIT 500", args), st=st, q=q,
                               statuses=ALERT_STATUSES)

    @app.get("/processes")
    def processes():
        q = request.args.get("q", "").strip()
        like = f"%{q}%"
        rows = db.q("SELECT p.*, b.signature, b.verdict, b.state FROM processes p LEFT JOIN binaries b ON b.sha256=p.sha256 "
                    "WHERE ?='' OR p.name LIKE ? OR p.exe LIKE ? OR p.sha256 LIKE ? OR p.username LIKE ? "
                    "ORDER BY p.first_seen DESC LIMIT 500", (q, like, like, like, like))
        return render_template("processes.html", rows=rows, q=q)

    @app.get("/network")
    def network():
        q = request.args.get("q", "").strip()
        nonstd = request.args.get("nonstd") == "1"
        like = f"%{q}%"
        rows = db.q("SELECT * FROM connections WHERE (?='' OR process LIKE ? OR rip LIKE ? OR CAST(rport AS TEXT)=?) "
                    "AND (?=0 OR nonstd=1) ORDER BY id DESC LIMIT 500", (q, like, like, q, int(nonstd)))
        return render_template("network.html", rows=rows, q=q, nonstd=nonstd)

    @app.get("/binaries")
    def binaries():
        q = request.args.get("q", "").strip()
        like = f"%{q}%"
        rows = db.q("SELECT * FROM binaries WHERE ?='' OR sha256 LIKE ? OR path LIKE ? OR rules LIKE ? OR state=? OR verdict=? "
                    "ORDER BY last_seen DESC LIMIT 500", (q, like, like, like, q, q))
        return render_template("binaries.html", rows=rows, q=q)

    @app.post("/binaries/<sha>/submit")
    def submit_now(sha: str):
        b = db.one("SELECT path FROM binaries WHERE sha256=?", (sha,))
        if not b or not os.path.isfile(b["path"]):
            flash("File no longer exists on disk.")
        else:
            db.x("UPDATE binaries SET state='pending', last_error=NULL WHERE sha256=?", (sha,))
            agent.bump("candidates")
            agent.wake_submit.set()
            flash("Queued for upload to the dashboard.")
        return redirect(url_for("binaries"))

    @app.get("/stats")
    def stats():
        if request.args.get("export") == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["minute_utc", "key", "value"])
            w.writerows((r["minute"], r["key"], r["value"]) for r in db.q("SELECT * FROM stats_minute ORDER BY minute, key"))
            return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=sentinel_stats.csv"})
        st = agent.stats()
        rule_hits = [(r, st["totals"].get(f"rule_{r}", 0)) for r in rules.RULES]
        minutes = 60 if request.args.get("range") != "24h" else 1440
        return render_template("stats.html", st=st, rule_hits=rule_hits, minutes=minutes,
                               telemetry=agent.series(["processes_observed", "connections_observed", "files_seen"], minutes),
                               pipeline=agent.series(["candidates", "uploads_sent", "upload_dedup", "upload_fail"], minutes))

    @app.route("/settings", methods=["GET", "POST"])
    def settings():
        test = None
        if request.method == "POST":
            action = request.form.get("action")
            form = {k: request.form.get(k, "").strip() for k in
                    ("dashboard_url", "api_key", "sensor_name", "submit_mode", "allowlist", "watchlist", "poll_seconds", "max_mb", "watch_dirs", "http_ports")}
            if not form["api_key"]:
                form["api_key"] = agent.cfg().get("api_key", "")  # blank field keeps the saved (masked) key
            for k in ("auto_submit", "http_watch", "notify"):
                form[k] = "1" if request.form.get(k) else "0"
            form["rules_enabled"] = ",".join(r for r in rules.RULES if request.form.get(f"rule_{r}"))
            if form["submit_mode"] not in ("allowlist", "rules"):
                form["submit_mode"] = "allowlist"
            for k, lo, default in (("poll_seconds", 0.5, "2"), ("max_mb", 1, "50")):
                try:
                    form[k] = f"{max(float(form[k]), lo):g}"
                except ValueError:
                    form[k] = default
            if action == "test":
                test = agent.check_connection({**agent.cfg(), **form})
            elif action == "disconnect":
                db.set_setting("api_key", "")
                agent._set_conn("not configured", "Disconnected by analyst.")
                flash("Disconnected: API key cleared.")
                return redirect(url_for("settings"))
            else:
                if not form["dashboard_url"].startswith(("http://", "https://")):
                    flash("Dashboard URL must start with http:// or https://")
                    return redirect(url_for("settings"))
                for k, v in form.items():
                    db.set_setting(k, v)
                agent.wake_heartbeat.set()
                agent.wake_submit.set()
                flash("Settings saved. Connection status updates within a few seconds.")
                return redirect(url_for("settings"))
        f = {**agent.cfg(), **form} if test else agent.cfg()  # after Test, keep what the analyst typed
        return render_template("settings.html", test=test, rules_all=rules.RULES, f=f,
                               enabled=set(f["rules_enabled"].split(",")))

    if start_agent:
        agent.start()
    return app


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SA2 Sentinel EDR agent + console")
    ap.add_argument("--port", type=int, default=8001)
    args = ap.parse_args(argv)
    os.chdir(ROOT)
    app = create_app()
    agent: Agent = app.config["AGENT"]
    print(f"\n  SA2 Sentinel   http://127.0.0.1:{args.port}/   (console is bound to localhost only)")
    print(f"  Elevated:      {agent.elevated}  {'' if agent.elevated else '(run as Administrator for full process/connection visibility)'}")
    print(f"  Submit mode:   {agent.cfg()['submit_mode']}   Dashboard: {agent.cfg()['dashboard_url']}\n")
    app.run(host="127.0.0.1", port=args.port, threaded=True, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
