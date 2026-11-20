"""SA2 Sentinel: rules, CSRF guard, and allowlist transport of a BENIGN file to a real SA2 Scan dashboard."""

from __future__ import annotations

import os
import shutil
import threading
import time
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from src.edr import rules
from src.edr.app import create_app as create_console
from src.edr.core import Agent
from src.webscan.app import create_app as create_dashboard

ROOT = Path(__file__).resolve().parents[1]
BENIGN = Path(os.environ.get("SA2_TEST_BENIGN_PE", r"C:\Windows\System32\notepad.exe"))


def _dashboard_engine_ready() -> bool:
    """The transport test runs the real V8 engine: needs thrember and the downloaded EMBER2024 model."""
    try:
        import thrember  # noqa: F401
    except ImportError:
        return False
    from src.v8 import deploy
    return (deploy.ROOT / deploy.EMBER_MODEL).is_file()


def test_motw_and_rules(monkeypatch, tmp_path):
    m = rules.parse_motw("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://a/\r\nHostUrl=https://a/x.exe\r\n")
    assert m == {"zone": 3, "host_url": "https://a/x.exe", "referrer_url": "https://a/"}
    assert rules.nonstd_remote("8.8.8.8", 4444) and not rules.nonstd_remote("8.8.8.8", 443) and not rules.nonstd_remote("10.0.0.5", 4444)
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    f = {"path": str(tmp_path / "Downloads" / "a.exe"), "sha256": "a" * 64, "signature": "NotSigned", "motw": m,
         "remote": [("8.8.8.8", 4444)]}
    hits = rules.evaluate(f, set(rules.RULES), watchlist="a" * 64)
    assert hits == ["user_writable", "motw_internet", "unsigned", "nonstd_port", "watchlist"]
    assert rules.evaluate({**f, "signature": "Valid", "motw": None, "remote": []}, set(rules.RULES)) == ["user_writable"]
    assert rules.score(["user_writable"]) < rules.CANDIDATE_SCORE <= rules.score(["user_writable", "unsigned"])
    assert rules.on_list(None, f["path"].upper(), f"# demo\n{f['path']}\n")
    assert rules.trusted_path(r"C:\Windows\System32\cmd.exe") and not rules.trusted_path(f["path"])


def test_console_csrf_and_pages(tmp_path):
    app = create_console(tmp_path / "edr", start_agent=False)
    c = app.test_client()
    for url in ("/", "/alerts", "/processes", "/network", "/binaries", "/stats", "/settings"):
        assert c.get(url, base_url="http://127.0.0.1:8001").status_code == 200, url
    assert c.get("/", base_url="http://evil.example").status_code == 403
    assert c.post("/settings", data={"action": "save", "dashboard_url": "http://evil"}, base_url="http://127.0.0.1:8001").status_code == 400
    agent = app.config["AGENT"]
    assert agent.cfg()["dashboard_url"] == "http://127.0.0.1:8000"
    with c.session_transaction(base_url="http://127.0.0.1:8001") as s:
        token = s["csrf"]
    allow = BENIGN
    if not allow.is_file():  # off Windows: any existing benign file works for the allowlist collector
        allow = tmp_path / "benign_stub.exe"
        allow.write_bytes(b"MZ" + b"\x00" * 62)
    form = {"csrf": token, "action": "save", "dashboard_url": "http://127.0.0.1:8000", "sensor_name": "t", "submit_mode": "allowlist",
            "allowlist": str(allow), "watchlist": "", "poll_seconds": "2", "max_mb": "50", "watch_dirs": str(tmp_path), "auto_submit": "on"}
    assert c.post("/settings", data=form, base_url="http://127.0.0.1:8001").status_code == 302
    assert agent.cfg()["max_mb"] == "50"
    agent.collect_once()  # settings saved via the form must be usable by the collector (regression: int("50.0"))
    assert agent.db.val("SELECT state FROM binaries WHERE origin='allowlist'") == "pending"


@pytest.mark.skipif(not BENIGN.is_file(), reason="needs Windows notepad.exe (or SA2_TEST_BENIGN_PE)")
@pytest.mark.skipif(not _dashboard_engine_ready(), reason="needs thrember and the downloaded EMBER2024 model")
def test_allowlist_transport_to_dashboard(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("SA2_BN", "0")  # never restart a running Binary Ninja from the test suite
    dash = create_dashboard(tmp_path / "dash")  # real V8 engine (EMBER2024 fallback path), background worker
    srv = make_server("127.0.0.1", 0, dash, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        agent = Agent(tmp_path / "edr")
        key = dash.config["DB"].setting("api_key")
        app_dir = tmp_path / "smoke"
        app_dir.mkdir()
        other = app_dir / "not_listed.exe"
        target = app_dir / "benign_test_app.exe"
        shutil.copy(BENIGN, target)
        shutil.copy(BENIGN, other)
        other.write_bytes(other.read_bytes() + b"\x00")  # different hash, not on the allowlist
        for k, v in {"dashboard_url": f"http://127.0.0.1:{srv.server_port}", "api_key": key,
                     "submit_mode": "allowlist", "allowlist": str(target), "sensor_name": "pytest-sensor"}.items():
            agent.db.set_setting(k, v)
        cfg = agent.cfg()
        sha_other = agent.consider(str(other), "file", cfg)
        sha = agent.consider(str(target), "allowlist", cfg)
        assert agent.db.val("SELECT state FROM binaries WHERE sha256=?", (sha_other,)) == "recorded"
        assert agent.db.val("SELECT state FROM binaries WHERE sha256=?", (sha,)) == "pending"
        for _ in range(60):
            agent.submit_once()
            if agent.db.val("SELECT state FROM binaries WHERE sha256=?", (sha,)) == "done":
                break
            time.sleep(0.5)
        b = agent.db.one("SELECT * FROM binaries WHERE sha256=?", (sha,))
        assert b["state"] == "done" and b["verdict"] == "benign", b
        assert agent.db.one("SELECT status, note FROM alerts WHERE sha256=?", (sha,)) == {"status": "Resolved", "note": "auto: benign verdict"}
        sub = dash.config["DB"].one("SELECT source, sensor_id, filename FROM submissions WHERE sha256=?", (sha,))
        assert sub == {"source": "edr", "sensor_id": "pytest-sensor", "filename": "benign_test_app.exe"}
        assert dash.config["DB"].val("SELECT COUNT(*) FROM files WHERE sha256=?", (sha_other,)) == 0
        agent.heartbeat_once()
        assert agent.conn["state"] == "connected"
        assert dash.config["DB"].one("SELECT sensor_id FROM sensors") == {"sensor_id": "pytest-sensor"}
        assert agent.stats()["totals"]["uploads_sent"] == 1
    finally:
        srv.shutdown()


def test_http_server_files_are_found_downloaded_and_queued(tmp_path, monkeypatch):
    import functools
    import http.server

    import psutil

    from src.edr import httpwatch

    monkeypatch.setattr(httpwatch, "is_http_server", lambda cmd: False)  # only the test server's port is watched, not real servers on this PC
    served = tmp_path / "www"
    (served / "sub").mkdir(parents=True)
    (served / "tool.exe").write_bytes(b"MZ" + b"\x00" * 64)
    (served / "sub" / "lib.dll").write_bytes(b"MZ" + b"\x01" * 64)
    (served / "notes.exe").write_bytes(b"not a pe")  # wrong magic: ignored
    (served / "readme.txt").write_text("hi")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(served))
    handler.log_message = lambda *a, **k: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        agent = Agent(tmp_path / "edr")
        agent.db.set_setting("http_ports", str(port))
        agent.http_scan(psutil.net_connections("inet"), agent.cfg())
        rows = {Path(r["path"]).name: r for r in agent.db.q("SELECT * FROM binaries")}
        assert set(rows) == {"tool.exe", "lib.dll"}
        assert all(r["origin"] == "http" and r["state"] == "pending" for r in rows.values())  # uploaded even in allowlist mode
        assert f"127.0.0.1:{port}/tool.exe" in rows["tool.exe"]["meta_json"]
        agent.http_scan(psutil.net_connections("inet"), agent.cfg())  # unchanged files are not fetched again
        assert agent.db.val("SELECT COUNT(*) FROM binaries") == 2
        agent.db.set_setting("http_watch", "0")
        (served / "new.exe").write_bytes(b"MZ" + b"\x02" * 64)
        agent._http_probed.clear()
        agent.http_scan(psutil.net_connections("inet"), agent.cfg())
        assert agent.db.val("SELECT COUNT(*) FROM binaries") == 2
    finally:
        srv.shutdown()


def test_toast_sent_with_report_url(monkeypatch, tmp_path):
    from src.edr import notify

    real, calls = notify.toast, []
    monkeypatch.setattr(notify, "toast", lambda *a: calls.append(a))
    agent = Agent(tmp_path / "edr")
    row = {"sha256": "a" * 64, "path": "C:/x/evil.exe", "origin": "http", "meta_json": '{"url": "http://127.0.0.1:8000/evil.exe"}'}
    agent._notify(row, "sent to SA2 Scan for analysis", agent.cfg())
    title, msg, url = calls[0]
    assert "evil.exe" in title and "127.0.0.1:8000/evil.exe" in msg and url == "http://127.0.0.1:8000/file/" + "a" * 64
    agent.db.set_setting("notify", "0")
    agent._notify(row, "x", agent.cfg())
    assert len(calls) == 1
    assert real("t", "m", "file:///etc/passwd") is False  # only http(s) links


def test_http_file_already_scanned_is_resubmitted_when_hosted_again(tmp_path, monkeypatch):
    import functools
    import http.server

    import psutil

    from src.edr import httpwatch

    monkeypatch.setattr(httpwatch, "is_http_server", lambda cmd: False)  # only the test server's port is watched, not real servers on this PC
    served = tmp_path / "www"
    served.mkdir()
    (served / "tool.exe").write_bytes(b"MZ" + b"\x00" * 64)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(served))
    handler.log_message = lambda *a, **k: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        agent = Agent(tmp_path / "edr")
        agent.db.set_setting("http_ports", str(port))
        agent.http_scan(psutil.net_connections("inet"), agent.cfg())
        sha = agent.db.val("SELECT sha256 FROM binaries")
        agent.db.x("UPDATE binaries SET state='done', verdict='benign' WHERE sha256=?", (sha,))  # scanned earlier
        agent._http_probed.clear()
        agent.http_scan(psutil.net_connections("inet"), agent.cfg())
        assert agent.db.val("SELECT state FROM binaries") == "done"  # same server, same file: nothing new
        agent._http_pid[port] = -1  # a different server process now listens on the port
        agent._http_probed.clear()
        agent.http_scan(psutil.net_connections("inet"), agent.cfg())
        assert agent.db.val("SELECT state FROM binaries") == "pending"  # queued again, so it uploads and notifies
    finally:
        srv.shutdown()
