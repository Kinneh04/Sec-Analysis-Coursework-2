"""SA2 Sentinel agent: process/network/download telemetry, rule evaluation, submission to SA2 Scan, stats.

Detection only: files are read (hashed / uploaded), never executed, and no process is killed or blocked.
"""

from __future__ import annotations

import ctypes
import json
import os
import socket
import statistics
import threading
import time
import urllib.error
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psutil

from src.common.hashing import sha256_file
from src.common.sqlite_db import DB
from src.common.winsig import signature_status
from src.edr import rules
from src.edr.client import Client

AGENT_VERSION = "1.0.0"
HEARTBEAT_SECONDS = 30
SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS processes(pid INTEGER, create_time REAL, name TEXT, exe TEXT, ppid INTEGER, parent TEXT,
  username TEXT, sha256 TEXT, first_seen TEXT, conn_count INTEGER DEFAULT 0, PRIMARY KEY(pid, create_time));
CREATE TABLE IF NOT EXISTS connections(id INTEGER PRIMARY KEY, at TEXT, pid INTEGER, process TEXT, laddr TEXT,
  rip TEXT, rport INTEGER, status TEXT, nonstd INTEGER);
CREATE TABLE IF NOT EXISTS binaries(sha256 TEXT PRIMARY KEY, path TEXT, size INTEGER, first_seen TEXT, last_seen TEXT,
  signature TEXT, motw_json TEXT, rules TEXT, origin TEXT, state TEXT, verdict TEXT, probability REAL,
  submitted_at TEXT, verdict_at TEXT, meta_json TEXT, last_error TEXT);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE, path TEXT, host TEXT, cause TEXT,
  score INTEGER, verdict TEXT, status TEXT, created TEXT, updated TEXT, resolved TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS counters(key TEXT PRIMARY KEY, value INTEGER);
CREATE TABLE IF NOT EXISTS stats_minute(minute TEXT, key TEXT, value INTEGER, PRIMARY KEY(minute, key));
CREATE INDEX IF NOT EXISTS ix_conn_at ON connections(at);
"""
ALERT_STATUSES = ("Unresolved", "In Progress", "Resolved", "False Positive")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _secs(a: str, b: str) -> float:
    return (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds()


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def default_settings() -> dict[str, str]:
    home = Path.home()
    dirs = [home / "Downloads", os.environ.get("TEMP", ""), os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", "")]
    return {
        "dashboard_url": "http://127.0.0.1:8000", "api_key": "", "sensor_name": socket.gethostname(),
        "auto_submit": "1",
        # Safe default: only files explicitly on the allowlist are transported until the analyst switches to "rules".
        "submit_mode": "allowlist", "allowlist": "", "watchlist": "",
        "poll_seconds": "2", "max_mb": "50", "watch_dirs": "\n".join(str(d) for d in dirs if d),
        "rules_enabled": ",".join(rules.RULES),
    }


class Agent:
    def __init__(self, data_dir: Path):
        self.db = DB(Path(data_dir) / "edr.db", SCHEMA)
        for k, v in default_settings().items():
            if self.db.setting(k) is None:
                self.db.set_setting(k, v)
        self.started = time.time()
        self.elevated = is_admin()
        self.conn: dict[str, Any] = {"state": "not configured", "detail": "", "rtt_ms": None, "last_ok": None, "model_tag": None}
        self.loop_ms: deque[float] = deque(maxlen=300)
        self.wake_submit = threading.Event()
        self.wake_heartbeat = threading.Event()
        self._seen_procs: set[tuple] = set()
        self._seen_conns: set[tuple] = set()
        self._seen_files: dict[str, tuple] = {}
        self._hash_cache: dict[tuple, str] = {}
        self._remote: dict[int, set[tuple[str, int]]] = {}
        self._baseline = True
        self._last_purge = 0.0
        self._threads: list[threading.Thread] = []

    # ---------- settings / stats ----------
    def cfg(self) -> dict[str, str]:
        return {r["key"]: r["value"] for r in self.db.q("SELECT key, value FROM settings")}

    def client(self, cfg: dict[str, str] | None = None) -> Client | None:
        cfg = cfg or self.cfg()
        return Client(cfg["dashboard_url"], cfg["api_key"]) if cfg.get("dashboard_url") and cfg.get("api_key") else None

    def bump(self, key: str, n: int = 1) -> None:
        if not n:
            return
        minute = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
        self.db.x("INSERT INTO counters(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = value + excluded.value", (key, n))
        self.db.x("INSERT INTO stats_minute(minute, key, value) VALUES(?,?,?) "
                  "ON CONFLICT(minute, key) DO UPDATE SET value = value + excluded.value", (minute, key, n))

    def stats(self) -> dict[str, Any]:
        totals = {r["key"]: r["value"] for r in self.db.q("SELECT key, value FROM counters ORDER BY key")}
        lat = [_secs(b["submitted_at"], b["verdict_at"]) for b in
               self.db.q("SELECT submitted_at, verdict_at FROM binaries WHERE submitted_at IS NOT NULL AND verdict_at IS NOT NULL")]
        closed = self.db.q("SELECT created, resolved, status FROM alerts WHERE resolved IS NOT NULL AND COALESCE(note,'') NOT LIKE 'auto:%'")
        dwell = [_secs(a["created"], a["resolved"]) for a in closed]
        hb_ok, hb_fail = totals.get("heartbeat_ok", 0), totals.get("heartbeat_fail", 0)
        gauges = {
            "uptime_s": int(time.time() - self.started),
            "elevated": self.elevated,
            "connection_state": self.conn["state"],
            "unique_remote_ips": self.db.val("SELECT COUNT(DISTINCT rip) FROM connections") or 0,
            "binaries_known": self.db.val("SELECT COUNT(*) FROM binaries") or 0,
            "pending_uploads": self.db.val("SELECT COUNT(*) FROM binaries WHERE state='pending'") or 0,
            "awaiting_verdict": self.db.val("SELECT COUNT(*) FROM binaries WHERE state='queued'") or 0,
            "alerts_open": self.db.val("SELECT COUNT(*) FROM alerts WHERE status IN ('Unresolved','In Progress')") or 0,
            "loop_ms_median": round(statistics.median(self.loop_ms), 1) if self.loop_ms else None,
            "verdict_latency_s_median": round(statistics.median(lat), 2) if lat else None,
            "verdict_latency_s_p95": round(sorted(lat)[max(int(len(lat) * 0.95) - 1, 0)], 2) if lat else None,
            "dwell_s_median": round(statistics.median(dwell)) if dwell else None,
            "false_positive_rate": round(sum(a["status"] == "False Positive" for a in closed) / len(closed), 3) if closed else None,
            "heartbeat_success_rate": round(hb_ok / (hb_ok + hb_fail), 3) if hb_ok + hb_fail else None,
        }
        return {"totals": totals, "gauges": gauges}

    def series(self, keys: list[str], minutes: int = 60) -> dict[str, list[int]]:
        end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        labels = [(end - timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M") for i in range(minutes - 1, -1, -1)]
        rows = self.db.q(f"SELECT minute, key, value FROM stats_minute WHERE minute >= ? AND key IN ({','.join('?' * len(keys))})",
                         [labels[0], *keys])
        idx = {m: i for i, m in enumerate(labels)}
        out = {k: [0] * minutes for k in keys}
        for r in rows:
            if r["minute"] in idx:
                out[r["key"]][idx[r["minute"]]] = r["value"]
        return out

    # ---------- collection ----------
    def _hash(self, path: str) -> tuple[str, int] | None:
        try:
            st = os.stat(path)
        except OSError:
            return None
        key = (path, st.st_mtime_ns, st.st_size)
        if key not in self._hash_cache:
            try:
                self._hash_cache[key] = sha256_file(Path(path))
            except OSError:
                return None
        return self._hash_cache[key], st.st_size

    def consider(self, path: str, origin: str, cfg: dict[str, str], proc: dict | None = None, force: bool = False) -> str | None:
        """Hash + rules for one file; marks it pending for upload when policy says so. Returns sha256."""
        try:
            if os.path.getsize(path) > float(cfg.get("max_mb", "50")) * 1024 * 1024:
                return None
        except OSError:
            return None
        hs = self._hash(path)
        if hs is None:
            return None
        sha, size = hs
        try:
            with open(path, "rb") as fh:
                if fh.read(2) != b"MZ":
                    return sha
        except OSError:
            return sha
        row = self.db.one("SELECT * FROM binaries WHERE sha256=?", (sha,))
        motw = rules.read_motw(path)
        sig = row["signature"] if row and row["signature"] else signature_status(path)
        remote = sorted(self._remote.get(proc["pid"], set())) if proc else []
        hits = rules.evaluate({"path": path, "sha256": sha, "signature": sig, "motw": motw, "remote": remote},
                              set(cfg["rules_enabled"].split(",")), cfg.get("watchlist", ""))
        allowed = rules.on_list(sha, path, cfg.get("allowlist", ""))
        if cfg.get("submit_mode") == "allowlist":
            want = allowed
        else:
            want = allowed or rules.score(hits) >= rules.CANDIDATE_SCORE
        meta = {"origin": origin, "exe_path": path, "rules": hits, "motw": motw,
                "remote": [f"{ip}:{port}" for ip, port in remote], "allowlisted": allowed}
        if proc:
            meta.update(process=proc.get("name"), pid=proc.get("pid"), parent=proc.get("parent"), user=proc.get("username"))
        t = now()
        if row is None:
            self.db.x("INSERT INTO binaries(sha256, path, size, first_seen, last_seen, signature, motw_json, rules, origin, state, meta_json) "
                      "VALUES(?,?,?,?,?,?,?,?,?, 'recorded', ?)",
                      (sha, path, size, t, t, sig, json.dumps(motw), ",".join(hits), origin, json.dumps(meta)))
            self.bump("binaries_new")
            if motw:
                self.bump("motw_seen")
            for h in hits:
                self.bump(f"rule_{h}")
            row = {"state": "recorded", "rules": ""}
        else:
            merged = sorted(set(filter(None, (row["rules"] or "").split(","))) | set(hits))
            for h in set(hits) - set(filter(None, (row["rules"] or "").split(","))):
                self.bump(f"rule_{h}")
            self.db.x("UPDATE binaries SET last_seen=?, path=?, rules=?, meta_json=? WHERE sha256=?",
                      (t, path, ",".join(merged), json.dumps({**meta, "rules": merged}), sha))
        if (want or force) and cfg.get("auto_submit") == "1" and row["state"] in ("recorded", "error"):
            self.db.x("UPDATE binaries SET state='pending', last_error=NULL WHERE sha256=?", (sha,))
            self.bump("candidates")
            self.wake_submit.set()
        return sha

    def collect_once(self) -> None:
        t0 = time.perf_counter()
        cfg = self.cfg()
        procs: dict[int, dict] = {}
        new: list[dict] = []
        live: set[tuple] = set()
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "username", "create_time"]):
            info = p.info
            key = (info["pid"], info["create_time"])
            procs[info["pid"]] = info
            live.add(key)
            if key not in self._seen_procs:
                new.append(info)
        self._seen_procs = live
        for info in new:
            info["parent"] = (procs.get(info["ppid"]) or {}).get("name")
            exe = info.get("exe")
            sha = None
            if exe and not rules.trusted_path(exe):
                sha = self.consider(exe, "process", cfg, info)
            self.db.x("INSERT OR IGNORE INTO processes(pid, create_time, name, exe, ppid, parent, username, sha256, first_seen) "
                      "VALUES(?,?,?,?,?,?,?,?,?)", (info["pid"], info["create_time"], info["name"], exe, info["ppid"],
                                                    info["parent"], info["username"], sha, now()))
        self.bump("processes_observed", len(new))

        try:
            conns = psutil.net_connections("inet")
        except (psutil.AccessDenied, OSError):
            conns = []
        live_c: set[tuple] = set()
        n_new = 0
        for c in conns:
            if not c.raddr:
                continue
            key = (c.pid, c.laddr, c.raddr)
            live_c.add(key)
            if key in self._seen_conns:
                continue
            n_new += 1
            proc = procs.get(c.pid or -1, {})
            nonstd = rules.nonstd_remote(c.raddr.ip, c.raddr.port)
            self.db.x("INSERT INTO connections(at, pid, process, laddr, rip, rport, status, nonstd) VALUES(?,?,?,?,?,?,?,?)",
                      (now(), c.pid, proc.get("name"), f"{c.laddr.ip}:{c.laddr.port}", c.raddr.ip, c.raddr.port, c.status, int(nonstd)))
            if c.pid:
                self.db.x("UPDATE processes SET conn_count = conn_count + 1 WHERE pid=? AND create_time=?", (c.pid, proc.get("create_time")))
            if nonstd and c.pid and proc.get("exe") and not rules.trusted_path(proc["exe"]):
                self._remote.setdefault(c.pid, set()).add((c.raddr.ip, c.raddr.port))
                self.consider(proc["exe"], "process", cfg, {**proc, "parent": (procs.get(proc.get("ppid")) or {}).get("name")})
        self._seen_conns = live_c
        self._remote = {pid: r for pid, r in self._remote.items() if pid in procs}
        self.bump("connections_observed", n_new)

        n_files = 0
        for d in filter(None, (x.strip() for x in cfg["watch_dirs"].splitlines())):
            try:
                entries = list(os.scandir(os.path.expandvars(d)))
            except OSError:
                continue
            for e in entries:
                try:
                    if not e.is_file():
                        continue
                    st = e.stat()
                except OSError:
                    continue
                sig = (st.st_mtime_ns, st.st_size)
                if self._seen_files.get(e.path) == sig:
                    continue
                self._seen_files[e.path] = sig
                if self._baseline:
                    continue  # files already present at start-up are not "new downloads"
                n_files += 1
                self.consider(e.path, "file", cfg)
        self.bump("files_seen", n_files)

        for path in rules.list_paths(cfg.get("allowlist", "")):
            if os.path.isfile(path):
                self.consider(path, "allowlist", cfg)
        self._baseline = False
        self.loop_ms.append((time.perf_counter() - t0) * 1000)

        if time.time() - self._last_purge > 3600:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=7))
            self.db.x("DELETE FROM stats_minute WHERE minute < ?", (cutoff.strftime("%Y-%m-%dT%H:%M"),))
            self.db.x("DELETE FROM connections WHERE at < ?", (cutoff.isoformat(timespec="seconds"),))
            self.db.x("DELETE FROM processes WHERE first_seen < ?", (cutoff.isoformat(timespec="seconds"),))
            self._last_purge = time.time()

    # ---------- submission ----------
    def _set_conn(self, state: str, detail: str = "", **kw: Any) -> None:
        self.conn.update(state=state, detail=detail, **kw)
        if state == "connected":
            self.conn["last_ok"] = now()

    def check_connection(self, cfg: dict[str, str] | None = None) -> dict[str, Any]:
        """Ping with the given (or saved) settings. Does not save anything."""
        cfg = cfg or self.cfg()
        cl = self.client(cfg)
        if cl is None:
            return {"state": "not configured", "detail": "Dashboard URL and API key are required."}
        try:
            st, js, ms = cl.ping()
        except (urllib.error.URLError, OSError, ValueError) as e:
            return {"state": "unreachable", "detail": str(getattr(e, "reason", e))}
        if st == 200 and js and js.get("ok"):
            return {"state": "connected", "detail": f"{js.get('server')} · model {js.get('model_tag')}", "rtt_ms": ms,
                    "model_tag": js.get("model_tag"), "thresholds": js.get("thresholds")}
        if st == 401:
            return {"state": "unauthorized", "detail": "API key rejected (401)."}
        return {"state": "error", "detail": f"HTTP {st}"}

    def _apply_report(self, sha: str, rep: dict[str, Any], cfg: dict[str, str]) -> None:
        verdict, prob = rep.get("verdict"), rep.get("probability")
        t = now()
        self.db.x("UPDATE binaries SET state='done', verdict=?, probability=?, verdict_at=? WHERE sha256=?", (verdict, prob, t, sha))
        self.bump(f"verdict_{verdict or 'unknown'}")
        b = self.db.one("SELECT path, rules, origin FROM binaries WHERE sha256=?", (sha,)) or {}
        benign = verdict == "benign"
        if self.db.x("INSERT OR IGNORE INTO alerts(sha256, path, host, cause, score, verdict, status, created, updated, resolved, note) "
                     "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                     (sha, b.get("path"), cfg["sensor_name"], b.get("rules") or b.get("origin"),
                      round((prob or 0) * 100), verdict, "Resolved" if benign else "Unresolved", t, t,
                      t if benign else None, "auto: benign verdict" if benign else None)):
            self.bump("alerts_created")

    def submit_once(self) -> None:
        cfg = self.cfg()
        cl = self.client(cfg)
        if cl is None:
            self._set_conn("not configured", "Set the dashboard URL and API key on the Settings page.")
            return
        try:
            for b in self.db.q("SELECT * FROM binaries WHERE state='pending' ORDER BY first_seen LIMIT 10"):
                st, rep = cl.lookup(b["sha256"])
                if st == 401:
                    self._set_conn("unauthorized", "API key rejected (401).")
                    return
                if st == 200:
                    self.bump("upload_dedup")
                    self.db.x("UPDATE binaries SET state='queued', submitted_at=? WHERE sha256=?", (now(), b["sha256"]))
                    continue
                hs = self._hash(b["path"])
                if hs is None or hs[0] != b["sha256"]:
                    self.db.x("UPDATE binaries SET state='error', last_error='file moved or changed before upload' WHERE sha256=?", (b["sha256"],))
                    self.bump("upload_fail")
                    continue
                meta = {**json.loads(b["meta_json"] or "{}"), "source": "edr", "sensor_id": cfg["sensor_name"]}
                st, js = cl.upload(Path(b["path"]).name, Path(b["path"]).read_bytes(), meta)
                if st == 202:
                    self.db.x("UPDATE binaries SET state='queued', submitted_at=? WHERE sha256=?", (now(), b["sha256"]))
                    self.bump("uploads_sent")
                else:
                    err = (js or {}).get("error", f"HTTP {st}")
                    self.db.x("UPDATE binaries SET state='error', last_error=? WHERE sha256=?", (err, b["sha256"]))
                    self.bump("upload_fail")
            for b in self.db.q("SELECT sha256 FROM binaries WHERE state='queued' LIMIT 50"):
                st, rep = cl.lookup(b["sha256"])
                if st == 200 and rep.get("status") in ("done", "error"):
                    self._apply_report(b["sha256"], rep, cfg)
        except (urllib.error.URLError, OSError) as e:
            self._set_conn("unreachable", str(getattr(e, "reason", e)))

    def heartbeat_once(self) -> None:
        cfg = self.cfg()
        cl = self.client(cfg)
        if cl is None:
            self._set_conn("not configured", "Set the dashboard URL and API key on the Settings page.")
            return
        res = self.check_connection(cfg)
        if res["state"] == "connected":
            try:
                st = cl.heartbeat({"sensor_id": cfg["sensor_name"], "hostname": socket.gethostname(),
                                   "agent_version": AGENT_VERSION, "started_at": datetime.fromtimestamp(self.started, timezone.utc).isoformat(),
                                   "stats": self.stats()})
            except (urllib.error.URLError, OSError) as e:
                st, res = 0, {"state": "unreachable", "detail": str(e)}
            if st != 200 and res["state"] == "connected":
                res = {"state": "error", "detail": f"heartbeat HTTP {st}"}
        self.bump("heartbeat_ok" if res["state"] == "connected" else "heartbeat_fail")
        self._set_conn(res["state"], res.get("detail", ""), rtt_ms=res.get("rtt_ms"), model_tag=res.get("model_tag"))

    # ---------- threads ----------
    def _loop(self, fn, interval, event: threading.Event) -> None:
        while True:
            try:
                fn()
            except Exception as e:  # a bad poll must not kill the agent
                print(f"[sentinel] {fn.__name__}: {type(e).__name__}: {e}", flush=True)
            if event.wait(interval() if callable(interval) else interval):
                event.clear()

    def start(self) -> None:
        poll = lambda: max(float(self.db.setting("poll_seconds", "2") or 2), 0.5)  # noqa: E731
        loops = ((self.collect_once, poll, threading.Event()), (self.submit_once, 2, self.wake_submit),
                 (self.heartbeat_once, HEARTBEAT_SECONDS, self.wake_heartbeat))
        for fn, iv, ev in loops:
            t = threading.Thread(target=self._loop, args=(fn, iv, ev), daemon=True, name=fn.__name__)
            t.start()
            self._threads.append(t)
