"""SA2 Scan console: auth, upload -> scan -> report, explanations, dedup, every page renders with data. Benign files only.

The malicious-verdict UI is exercised with a STUB engine (labelled as such); no malware is used.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from src.webscan import explain
from src.webscan.app import create_app

ROOT = Path(__file__).resolve().parents[1]
NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")


def stub_scan(verdict: str, signals: list | None = None):
    def scan(path: Path) -> dict:
        p = 0.99 if verdict == "malicious" else 0.01
        eng = [{"name": "pe_v3", "model_tag": "STUB", "probability": p, "threshold": 0.96, "threshold_source": "stub",
                "frozen_threshold": 0.89, "flagged": p >= 0.96, "recommended": True},
               {"name": "pe_v1s", "model_tag": "STUB", "probability": p, "threshold": 0.91, "threshold_source": "frozen",
                "frozen_threshold": 0.91, "flagged": p >= 0.91, "recommended": False}]
        top = [{"feature": "pe3_overlay_entropy", "group": "overlay", "title": "Entropy of the appended data", "value": "7.99 bits/byte",
                "raw_value": 7.99, "contribution": 0.9 if p > 0.5 else -0.9, "direction": "malicious", "strength": "strong", "typical": None}]
        return {"report_version": 4, "signals": signals or [],
                "pe": {"imports": {"kernel32.dll": ["CreateFileW", "WriteProcessMemory"]}, "imphash": "stub", "sections": [], "signature": {"status": "NotSigned"}},
                "engines": eng, "explanation": {"base_log_odds": 0.0, "base_probability": 0.5, "final_probability": p,
                                                "groups": [{"group": "overlay", "label": "Appended data (overlay)", "contribution": top[0]["contribution"]}],
                                                "top": top},
                "top_features": [], "verdict": verdict, "flag_count": sum(e["flagged"] for e in eng), "engine_count": 2,
                "probability": p, "scan_ms": 1}
    return scan


@pytest.fixture
def make(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)

    def _make(scan_fn=None, login=True):
        app = create_app(tmp_path / "dash", start_worker=False, scan_fn=scan_fn)
        app.config["TESTING"] = True
        c = app.test_client()
        if login:
            assert c.post("/login", data={"password": app.config["DB"].setting("admin_password")}).status_code == 302
        return app, c, app.config["DB"].setting("api_key")
    return _make


def fake_pe(tag: bytes = b"x") -> bytes:
    return b"MZ" + b"\x00" * 62 + tag


def test_auth_and_rejections(make):
    app, c, key = make(stub_scan("benign"), login=False)
    assert c.get("/").status_code == 302 and "/login" in c.get("/").headers["Location"]
    assert c.post("/upload", data={"file": (io.BytesIO(fake_pe()), "a.exe")}).status_code == 302  # to login, not stored
    assert app.config["DB"].val("SELECT COUNT(*) FROM files") == 0
    assert c.post("/login", data={"password": "wrong"}).status_code == 200
    assert c.get("/api/v1/ping").status_code == 401
    assert c.get("/api/v1/ping", headers={"X-API-Key": key}).get_json()["model_tag"] == "v3.2"
    r = c.post("/api/v1/files", headers={"X-API-Key": key}, data={"file": (io.BytesIO(b"hello"), "a.txt")})
    assert r.status_code == 415


def test_dedup_stub_malicious_report_and_disposition(make):
    sigs = [{"id": "api_injection", "severity": "high", "title": "Process injection APIs", "evidence": "writeprocessmemory", "meaning": "m"}]
    app, c, key = make(stub_scan("malicious", sigs))
    h = {"X-API-Key": key}
    meta = json.dumps({"source": "edr", "sensor_id": "host1", "rules": ["unsigned"]})
    r1 = c.post("/api/v1/files", headers=h, data={"file": (io.BytesIO(fake_pe()), "t.exe"), "meta": meta})
    r2 = c.post("/api/v1/files", headers=h, data={"file": (io.BytesIO(fake_pe()), "t2.exe"), "meta": meta})
    assert (r1.get_json()["status"], r2.get_json()["status"]) == ("queued", "known")
    sha = r1.get_json()["sha256"]
    app.config["PROCESS"](sha)
    rep = c.get(f"/api/v1/files/{sha}", headers=h).get_json()
    assert rep["verdict"] == "malicious" and rep["flag_count"] == 2 and len(rep["submissions"]) == 2
    assert rep["assessment"]["label"] == "Consistent with malware indicators"
    page = c.get(f"/file/{sha}").get_data(as_text=True)
    assert "Consistent with malware indicators" in page and "Process injection APIs" in page and "STUB" in page
    assert c.post(f"/file/{sha}/disposition", data={"disposition": "false_positive", "note": "test"}).status_code == 302
    assert app.config["DB"].val("SELECT disposition FROM files WHERE sha256=?", (sha,)) == "false_positive"
    assert c.get(f"/file/{sha}/csv").get_data(as_text=True).count("\n") == 2
    assert c.get("/submissions?disposition=false_positive").get_data(as_text=True).count(sha[:16]) >= 1


def test_every_page_renders_with_data(make):
    app, c, key = make(stub_scan("malicious"))
    hb = {"sensor_id": "host1", "hostname": "host1", "agent_version": "t",
          "stats": {"totals": {"uploads_sent": 3, "processes_observed": 9}, "gauges": {"uptime_s": 120}}}
    assert c.post("/api/v1/sensors/heartbeat", headers={"X-API-Key": key}, json=hb).status_code == 200
    r = c.post("/api/v1/files", headers={"X-API-Key": key}, data={"file": (io.BytesIO(fake_pe()), "t.exe"),
                                                                    "meta": json.dumps({"source": "edr", "sensor_id": "host1"})})
    app.config["PROCESS"](r.get_json()["sha256"])
    c.post("/api/v1/files", headers={"X-API-Key": key}, data={"file": (io.BytesIO(fake_pe(b"q")), "queued.exe")})  # left queued
    for url in ("/", "/dashboard", "/submissions", "/submissions?verdict=malicious&sort=score", "/submissions?verdict=borderline",
                "/insights", "/insights?only=flagged", "/sensors", "/sensors/host1", "/model", "/settings", "/glossary",
                "/search?q=.exe", f"/file/{r.get_json()['sha256']}", f"/file/{r.get_json()['sha256']}/print",
                "/submissions?export=csv", "/submissions?export=json"):
        resp = c.get(url)
        assert resp.status_code == 200, url
    assert "Online" in c.get("/sensors").get_data(as_text=True)
    assert c.get("/file/" + "0" * 64).status_code == 404
    assert c.get("/admin").status_code == 302 and c.get("/analyze").status_code == 302


def test_explain_nsis_signed_reads_as_likely_false_positive():
    sigs = explain.signals({"signature": {"status": "Valid", "signer": "Example Ltd"}, "sections": [{"name": ".ndata", "entropy": 0, "raw_size": 0, "rwx": False}],
                            "imports": {"kernel32.dll": ["CreateProcessW"]}, "version_info": {"ProductName": "x"}, "aslr": True, "dep": True},
                           b"MZ...NullsoftInst...")
    ids = {s["id"] for s in sigs}
    assert {"signed_valid", "format_nsis"} <= ids
    rep = {"verdict": "malicious", "probability": 0.99, "engines": [{"recommended": True, "threshold": 0.96}],
           "explanation": {"groups": [{"group": "overlay", "label": "Appended data (overlay)", "contribution": 1.2}], "top": []}}
    a = explain.assessment(rep, sigs)
    assert a["label"] == "Likely false positive - review" and "Example Ltd" in a["summary"]


def test_describe_resolves_hashed_buckets_to_file_names():
    from src.v3.pe_features_v3 import IMPORT_BUCKETS, SECTION_BUCKETS, stable_bucket
    ctx = explain.build_context([".ndata"], {"kernel32.dll": ["VirtualAllocEx"]}, [])
    b = stable_bucket("kernel32.dll:VirtualAllocEx", IMPORT_BUCKETS)
    assert "VirtualAllocEx" in explain.describe(f"pe3_imp_bucket_{b:04d}", ctx)[1]
    s = stable_bucket(".ndata", SECTION_BUCKETS)
    assert ".ndata" in explain.describe(f"pe3_secname_vsize_{s:02d}", ctx)[1]
    assert explain.describe("pe3_str_char_entropy", ctx)[1] == "Variety of characters in strings"
    assert explain.fmt_value(2048, "bytes") == "2.0 KB" and explain.fmt_value(1, "bool") == "yes"


@pytest.mark.skipif(not NOTEPAD.is_file(), reason="needs Windows notepad.exe")
def test_real_engine_on_benign_notepad(make):
    app, c, key = make()  # real V3.2 models
    r = c.post("/upload", data={"file": (io.BytesIO(NOTEPAD.read_bytes()), "notepad.exe")})
    sha = r.headers["Location"].rsplit("/", 1)[-1]
    app.config["PROCESS"](sha)
    rep = c.get(f"/file/{sha}/json").get_json()
    assert rep["verdict"] == "benign" and rep["engine_count"] == 2
    assert abs(rep["probability"] - 0.0063) < 0.001
    assert rep["pe"]["signature"]["status"] == "Valid" and rep["explanation"]["top"]
    assert abs(rep["explanation"]["final_probability"] - rep["probability"]) < 1e-4  # SHAP sums back to the score
    assert rep["assessment"]["label"] == "No significant concern"
    assert "Score breakdown" in c.get(f"/file/{sha}").get_data(as_text=True)
