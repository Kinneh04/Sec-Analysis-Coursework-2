"""SA2 Scan dashboard: upload → scan → report, API auth, dedup, admin pages. Benign files only.

The malicious-verdict UI is exercised with a STUB engine (labelled as such); no malware is used.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from src.webscan.app import create_app

ROOT = Path(__file__).resolve().parents[1]
NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")


def stub_scan(verdict: str):
    def scan(path: Path) -> dict:
        p = 0.99 if verdict == "malicious" else 0.01
        eng = [{"name": "pe_v3", "model_tag": "STUB", "probability": p, "threshold": 0.96, "threshold_source": "stub",
                "frozen_threshold": 0.89, "flagged": p >= 0.96, "recommended": True},
               {"name": "pe_v1s", "model_tag": "STUB", "probability": p, "threshold": 0.91, "threshold_source": "frozen",
                "frozen_threshold": 0.91, "flagged": p >= 0.91, "recommended": False}]
        return {"pe": {"imports": {"kernel32.dll": ["CreateFileW"]}, "imphash": "stub", "sections": []}, "engines": eng,
                "top_features": [{"feature": "stub_feature", "contribution": 1.0}], "verdict": verdict,
                "flag_count": sum(e["flagged"] for e in eng), "engine_count": 2, "probability": p, "scan_ms": 1}
    return scan


@pytest.fixture
def make(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)

    def _make(scan_fn=None):
        app = create_app(tmp_path / "dash", start_worker=False, scan_fn=scan_fn)
        app.config["TESTING"] = True
        return app, app.test_client(), app.config["DB"].setting("api_key")
    return _make


def fake_pe(tag: bytes = b"x") -> bytes:
    return b"MZ" + b"\x00" * 62 + tag


def test_non_pe_rejected_and_key_required(make):
    app, c, key = make(stub_scan("benign"))
    assert c.get("/api/v1/ping").status_code == 401
    assert c.get("/api/v1/ping", headers={"X-API-Key": "wrong"}).status_code == 401
    assert c.get("/api/v1/ping", headers={"X-API-Key": key}).get_json()["model_tag"] == "v3.2"
    r = c.post("/api/v1/files", headers={"X-API-Key": key}, data={"file": (io.BytesIO(b"hello"), "a.txt")})
    assert r.status_code == 415
    assert app.config["DB"].val("SELECT COUNT(*) FROM files") == 0


def test_dedup_and_stub_malicious_report(make):
    app, c, key = make(stub_scan("malicious"))
    h = {"X-API-Key": key}
    meta = json.dumps({"source": "edr", "sensor_id": "host1", "rules": ["unsigned"]})
    r1 = c.post("/api/v1/files", headers=h, data={"file": (io.BytesIO(fake_pe()), "t.exe"), "meta": meta})
    r2 = c.post("/api/v1/files", headers=h, data={"file": (io.BytesIO(fake_pe()), "t2.exe"), "meta": meta})
    assert r1.status_code == r2.status_code == 202
    assert (r1.get_json()["status"], r2.get_json()["status"]) == ("queued", "known")
    sha = r1.get_json()["sha256"]
    app.config["PROCESS"](sha)
    rep = c.get(f"/api/v1/files/{sha}", headers=h).get_json()
    assert rep["status"] == "done" and rep["verdict"] == "malicious" and rep["flag_count"] == 2
    assert len(rep["submissions"]) == 2 and rep["names"] == ["t.exe", "t2.exe"]
    page = c.get(f"/file/{sha}").get_data(as_text=True)
    assert "2/2 models flag this file" in page and "STUB" in page
    assert c.get(f"/file/{sha}/csv").get_data(as_text=True).count("\n") == 2


def test_heartbeat_and_admin_pages(make):
    app, c, key = make(stub_scan("benign"))
    assert c.get("/admin").status_code == 302
    hb = {"sensor_id": "host1", "hostname": "host1", "agent_version": "t", "stats": {"totals": {"uploads_sent": 3}, "gauges": {}}}
    assert c.post("/api/v1/sensors/heartbeat", headers={"X-API-Key": key}, json=hb).status_code == 200
    r = c.post("/api/v1/files", headers={"X-API-Key": key}, data={"file": (io.BytesIO(fake_pe()), "t.exe"),
                                                                    "meta": json.dumps({"source": "edr", "sensor_id": "host1"})})
    app.config["PROCESS"](r.get_json()["sha256"])  # admin pages must render with real rows, not only empty tables
    c.post("/admin/login", data={"password": app.config["DB"].setting("admin_password")})
    for url in ("/admin", "/admin/submissions", "/admin/matrix", "/admin/sensors", "/admin/sensors/host1", "/admin/model",
                "/admin/submissions?export=csv"):
        assert c.get(url).status_code == 200, url
    assert "Online" in c.get("/admin/sensors").get_data(as_text=True)


@pytest.mark.skipif(not NOTEPAD.is_file(), reason="needs Windows notepad.exe")
def test_real_engine_on_benign_notepad(make):
    app, c, key = make()  # real V3.2 models
    r = c.post("/upload", data={"file": (io.BytesIO(NOTEPAD.read_bytes()), "notepad.exe")})
    sha = r.headers["Location"].rsplit("/", 1)[-1]
    app.config["PROCESS"](sha)
    rep = c.get(f"/file/{sha}/json").get_json()
    assert rep["verdict"] == "benign" and rep["engine_count"] == 2
    assert abs(rep["probability"] - 0.0063) < 0.001
    assert rep["pe"]["signature"] == "Valid" and rep["top_features"]
