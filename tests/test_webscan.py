"""SA2 Scan console: auth, upload -> scan -> report, decision paths, exports, every page renders. Benign files only.

Verdicts in most tests come from STUB engines shaped like src.webscan.scanner output (labelled as such); no malware is used.
Nothing here needs Binary Ninja, the network or the EMBER2024 model; the one real-engine test skips without them.
"""

from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path

import pytest

from src.webscan import app as app_mod
from src.webscan import explain, scanner
from src.webscan.app import create_app

ROOT = Path(__file__).resolve().parents[1]
NOTEPAD = Path(os.environ.get("SA2_TEST_BENIGN_PE", r"C:\Windows\System32\notepad.exe"))
THR = 0.31491410519549656
BORDER = 0.10
BLEND, R1 = scanner.ENGINE_BLEND, scanner.ENGINE_R1


def engines_for(p_blend: float, p_r1: float, covered: bool, reason: str = "covered") -> dict:
    blend = {"name": BLEND, "model_tag": "STUB", "probability": p_blend, "threshold": THR, "threshold_source": "frozen",
             "frozen_threshold": THR, "flagged": p_blend >= THR, "recommended": True,
             "coverage": "covered" if covered else "uncovered", "decision_path": "blend" if covered else "r1_fallback",
             "fallback_reason": None if covered else reason, "blend_margin": 0.42 if p_blend >= THR else -0.42,
             "r1_score": p_r1, "r1_logit": 0.0, "bn_score": 0.77 if covered else None, "bn_logit": 1.2 if covered else None,
             "w": 0.3, "t_blend": 0.5, "display_shift": -0.77, "scale_note": scanner.SCALE_NOTE}
    r1 = {"name": R1, "model_tag": "EMBER2024_PE", "probability": p_r1, "threshold": THR, "threshold_source": "frozen",
          "frozen_threshold": THR, "flagged": p_r1 >= THR, "recommended": False, "coverage": "n/a", "r1_score": p_r1}
    bn = {"covered": covered, "reason": reason, "note": f"STUB note ({reason})", "cap6_status": "ok" if covered else "not_run",
          "hl6_status": "ok" if covered else "not_run", "seconds": 12.5 if covered else 0.01, "url": "http://127.0.0.1:24642/mcp",
          "mode_enforced": covered, "prep": [], "cached": False}
    return {"engines": [blend, r1], "bn": bn, "timings_ms": {"ember": 50, "bn": 12500 if covered else 0, "score": 3},
            "decision_path": {"path": blend["decision_path"], "reason": reason, "note": bn["note"]}}


def stub_scan(p_blend: float, p_r1: float | None = None, covered: bool = True, reason: str = "covered", signals: list | None = None):
    p_r1 = p_blend if p_r1 is None else p_r1

    def scan(path: Path) -> dict:
        eng = engines_for(p_blend, p_r1, covered, reason)
        mal = p_blend >= THR
        top = [{"feature": "stub_feature", "group": "stub_group_not_in_GROUPS", "title": "Stub reason", "value": "1",
                "raw_value": 1.0, "contribution": 0.9 if mal else -0.9, "direction": "malicious", "strength": "strong", "typical": None}]
        return {"report_version": scanner.REPORT_VERSION, "signals": signals or [],
                "pe": {"imports": {"kernel32.dll": ["CreateFileW", "WriteProcessMemory"]}, "imphash": "stub", "sections": [],
                       "signature": {"status": "NotSigned"}},
                **eng, "explanation": {"base_log_odds": 0.0, "base_probability": 0.5, "final_probability": p_blend,
                                       "groups": [{"group": "stub_group_not_in_GROUPS", "label": "Stub group", "contribution": top[0]["contribution"]}],
                                       "top": top, "base_parts": {}},
                "top_features": [], "verdict": "malicious" if mal else "benign",
                "flag_count": sum(e["flagged"] for e in eng["engines"]), "engine_count": 2, "probability": p_blend, "scan_ms": 1}
    return scan


LEGACY_REPORT = {  # shape of a stored V3.2 report (report_version 4), before the V8 switch
    "report_version": 4, "signals": [], "pe": {"imports": {}, "imphash": "old", "sections": [], "signature": {"status": "NotSigned"}},
    "engines": [{"name": "pe_v3", "model_tag": "v3.2", "probability": 0.5, "threshold": 0.9603, "threshold_source": "deploy_calibrated",
                 "frozen_threshold": 0.89, "flagged": False, "recommended": True},
                {"name": "pe_v1s", "model_tag": "v3.2", "probability": 0.4, "threshold": 0.91, "threshold_source": "frozen",
                 "frozen_threshold": 0.91, "flagged": False, "recommended": False}],
    "explanation": {"base_probability": 0.5, "final_probability": 0.5, "groups": [{"group": "overlay", "label": "Appended data", "contribution": 0.1}],
                    "top": [{"feature": "pe3_x", "group": "overlay", "title": "Old reason", "value": "1", "contribution": 0.1, "strength": "weak", "typical": None}]},
    "top_features": [], "verdict": "benign", "flag_count": 0, "engine_count": 2, "probability": 0.5, "scan_ms": 5}


@pytest.fixture
def make(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    monkeypatch.setattr(scanner, "thresholds", lambda: {
        BLEND: {"threshold": THR, "source": "frozen", "frozen": THR, "scale": "display"},
        R1: {"threshold": THR, "source": "frozen", "frozen": THR, "scale": "probability"}})
    monkeypatch.setattr(app_mod, "borderline_cut", lambda thr: (BORDER, "test"))
    monkeypatch.setenv("SA2_BN", "0")  # settings page: no probe

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


def submit(app, c, key, tag: bytes, name: str, process: bool = True) -> str:
    r = c.post("/api/v1/files", headers={"X-API-Key": key}, data={"file": (io.BytesIO(fake_pe(tag)), name)})
    sha = r.get_json()["sha256"]
    if process:
        app.config["PROCESS"](sha)
    return sha


def add_legacy(app, sha: str = "a" * 64) -> str:
    app.config["DB"].x("INSERT INTO files(sha256, md5, sha1, size, name, first_seen, last_seen, status, verdict, probability, scan_ms, report_json) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (sha, "m" * 32, "s" * 40, 10, "old_v32.exe", "2026-11-01T00:00:00+00:00",
                                                           "2026-11-01T00:00:00+00:00", "done", "benign", 0.5, 5, json.dumps(LEGACY_REPORT)))
    app.config["DB"].x("INSERT INTO submissions(sha256, at, source, filename, meta_json) VALUES(?,?,?,?,?)",
                       (sha, "2026-11-01T00:00:00+00:00", "web", "old_v32.exe", "{}"))
    return sha


def test_auth_ping_and_rejections(make):
    app, c, key = make(stub_scan(0.01, covered=False, reason="bn_disabled"), login=False)
    assert c.get("/").status_code == 302 and "/login" in c.get("/").headers["Location"]
    assert c.post("/upload", data={"file": (io.BytesIO(fake_pe()), "a.exe")}).status_code == 302  # to login, not stored
    assert app.config["DB"].val("SELECT COUNT(*) FROM files") == 0
    assert c.post("/login", data={"password": "wrong"}).status_code == 200
    assert c.get("/api/v1/ping").status_code == 401
    ping = c.get("/api/v1/ping", headers={"X-API-Key": key}).get_json()
    assert ping["model_tag"] == "v8" and ping["decision_engine"] == BLEND
    assert ping["thresholds"] == {BLEND: THR, R1: THR}
    r = c.post("/api/v1/files", headers={"X-API-Key": key}, data={"file": (io.BytesIO(b"hello"), "a.txt")})
    assert r.status_code == 415


def test_borderline_band():
    assert app_mod.risk_band(0.5, THR, 0.2) == "high" and app_mod.risk_band(THR, THR, 0.2) == "high"
    assert app_mod.risk_band(0.25, THR, 0.2) == "elevated" and app_mod.risk_band(0.19, THR, 0.2) == "low"
    assert app_mod.risk_band(None, THR) == "none"


def test_borderline_cut_reads_reference(monkeypatch):
    monkeypatch.setattr(explain, "reference", lambda: {"r1_operating_points": {"fpr_0.05": 0.2}})
    assert app_mod.borderline_cut(THR) == (0.2, "EMBER2024 score at 5% training FPR")
    monkeypatch.setattr(explain, "reference", lambda: {})
    assert app_mod.borderline_cut(THR)[0] == app_mod.BORDERLINE_FALLBACK < THR
    monkeypatch.setattr(explain, "reference", lambda: {"r1_operating_points": {"fpr_0.05": 0.9}})  # above threshold: ignored
    assert app_mod.borderline_cut(THR)[0] == app_mod.BORDERLINE_FALLBACK


def test_blend_report_disposition_and_csv(make):
    sigs = [{"id": "api_injection", "severity": "high", "title": "Process injection APIs", "evidence": "writeprocessmemory", "meaning": "m"}]
    app, c, key = make(stub_scan(0.99, signals=sigs))
    h = {"X-API-Key": key}
    meta = json.dumps({"source": "edr", "sensor_id": "host1", "rules": ["unsigned"]})
    r1 = c.post("/api/v1/files", headers=h, data={"file": (io.BytesIO(fake_pe()), "t.exe"), "meta": meta})
    r2 = c.post("/api/v1/files", headers=h, data={"file": (io.BytesIO(fake_pe()), "t2.exe"), "meta": meta})
    assert (r1.get_json()["status"], r2.get_json()["status"]) == ("queued", "known")
    sha = r1.get_json()["sha256"]
    app.config["PROCESS"](sha)
    rep = c.get(f"/api/v1/files/{sha}", headers=h).get_json()
    assert rep["verdict"] == "malicious" and rep["flag_count"] == 2 and len(rep["submissions"]) == 2 and rep["risk"] == "high"
    page = c.get(f"/file/{sha}").get_data(as_text=True)
    assert "Decision path" in page and "EMBER2024 + Binary Ninja model" in page and "Process injection APIs" in page
    assert "0.7700" in page and "cap6" in page and "The engines disagree" not in page
    assert c.post(f"/file/{sha}/disposition", data={"disposition": "false_positive", "note": "test"}).status_code == 302
    assert app.config["DB"].val("SELECT disposition FROM files WHERE sha256=?", (sha,)) == "false_positive"
    rows = list(csv.DictReader(io.StringIO(c.get(f"/file/{sha}/csv").get_data(as_text=True))))
    assert len(rows) == 1 and rows[0]["decision_path"] == "blend" and rows[0]["fallback_reason"] == ""
    assert float(rows[0][f"{BLEND}_score"]) == 0.99 and rows[0][f"{R1}_flagged"] == "True" and rows[0]["bn_score"] == "0.77"
    assert not any("probability" in k for k in rows[0])
    assert c.get("/submissions?disposition=false_positive").get_data(as_text=True).count(sha[:16]) >= 1


def test_fallback_report_shows_reason(make):
    app, c, key = make(stub_scan(0.2, covered=False, reason="bn_unreachable"))
    sha = submit(app, c, key, b"f", "fb.exe")
    page = c.get(f"/file/{sha}").get_data(as_text=True)
    assert "EMBER2024 only" in page and "Binary Ninja not reachable" in page and "STUB note (bn_unreachable)" in page
    assert "not used" in page and "both engines are EMBER2024 on this file" in page
    rep = c.get(f"/file/{sha}/json").get_json()
    assert rep["risk"] == "elevated" and rep["verdict"] == "benign"  # 0.10 <= 0.2 < threshold: borderline, not flagged
    assert sha[:16] in c.get("/submissions?verdict=borderline").get_data(as_text=True)
    rows = list(csv.DictReader(io.StringIO(c.get("/submissions?export=csv").get_data(as_text=True))))
    assert rows[0]["decision_path"] == "r1_fallback" and rows[0]["fallback_reason"] == "bn_unreachable"


def test_engine_disagreement_is_visible(make):
    app, c, key = make(stub_scan(0.6, p_r1=0.2))  # covered: blend flags, EMBER2024 alone does not
    sha = submit(app, c, key, b"d", "dis.exe")
    page = c.get(f"/file/{sha}").get_data(as_text=True)
    assert "The engines disagree" in page and "EMBER2024 alone says <b>not malicious</b>" in page
    assert c.get(f"/file/{sha}/json").get_json()["flag_count"] == 1
    dash = c.get("/dashboard").get_data(as_text=True)
    assert "Same decision <b>0 / 1</b>" in dash and "Binary Ninja features used (V8 blend)" in dash
    rows = list(csv.DictReader(io.StringIO(c.get(f"/file/{sha}/csv").get_data(as_text=True))))
    assert rows[0]["engines_disagree"] == "True"


def test_disagreement_banner_attributes_the_threshold_offset(make):
    import math

    shift = math.log(THR / (1 - THR))
    r1m, bt, t_blend = -0.1, -0.02, -0.91947  # EMBER2024 just under, Binary Ninja slightly negative: the offset decides
    m = r1m + bt + shift - t_blend
    base = stub_scan(1 / (1 + math.exp(-(m + shift))), p_r1=1 / (1 + math.exp(-(r1m + shift))))

    def scan(path):
        rep = base(path)
        rep["engines"][0].update(r1_logit=r1m + shift, bn_logit=bt / 0.3, w=0.3, t_blend=t_blend, display_shift=shift, blend_margin=m)
        return rep

    app, c, key = make(scan)
    sha = submit(app, c, key, b"o", "offset.exe")
    page = c.get(f"/file/{sha}").get_data(as_text=True)
    assert "The engines disagree" in page and "threshold offset alone was enough to cross the threshold" in page
    assert "Flagged by the blend threshold offset - borderline, review" in page
    assert "Flagged by code analysis only" not in page and "Binary Ninja model moved the decision" not in page


def test_csv_export_neutralises_formula_cells(make):
    base = stub_scan(0.05)  # benign: blend_margin is the number -0.42

    def scan(path):
        rep = base(path)
        rep["pe"]["signature"] = {"status": "Valid", "signer": "=HYPERLINK(\"http://x\")"}
        return rep

    app, c, key = make(scan)
    sha = submit(app, c, key, b"f", "@SUM(1+1).exe")
    for url in (f"/file/{sha}/csv", "/submissions?export=csv"):
        row = list(csv.DictReader(io.StringIO(c.get(url).get_data(as_text=True))))[0]
        assert row["signer"] == "'=HYPERLINK(\"http://x\")"
        assert row["names"] == "'@SUM(1+1).exe"
        assert row["blend_margin"] == "-0.42"  # numeric cells untouched
    assert app_mod.csv_safe("-x") == "'-x" and app_mod.csv_safe("\tx") == "'\tx" and app_mod.csv_safe("\rx") == "'\rx"
    assert app_mod.csv_safe("+1") == "'+1" and app_mod.csv_safe(-1.5) == -1.5 and app_mod.csv_safe("ok") == "ok"


def test_scoring_error_cause_is_shown_on_the_report(make):
    def scan(path):
        return {"report_version": scanner.REPORT_VERSION, "verdict": "error", "error": "ember_failed:ValueError: bad_dim:12",
                "engines": [], "top_features": [], "explanation": {}, "pe": {}, "signals": [], "flag_count": 0, "engine_count": 0}

    app, c, key = make(scan)
    sha = submit(app, c, key, b"z", "broken.exe")
    page = c.get(f"/file/{sha}").get_data(as_text=True)
    assert "The file could not be scored" in page and "ember_failed:ValueError: bad_dim:12" in page
    assert c.get(f"/file/{sha}/json").get_json()["error"] == "ember_failed:ValueError: bad_dim:12"


def test_every_page_renders_with_blend_fallback_error_and_legacy(make):
    calls = {"n": 0}
    kinds = [stub_scan(0.99), stub_scan(0.05, covered=False, reason="bn_timeout"), stub_scan(0.6, p_r1=0.2)]

    def scan(path: Path) -> dict:
        calls["n"] += 1
        if calls["n"] == 4:
            raise RuntimeError("stub parser failure")
        return kinds[calls["n"] - 1](path)

    app, c, key = make(scan)
    hb = {"sensor_id": "host1", "hostname": "host1", "agent_version": "t",
          "stats": {"totals": {"uploads_sent": 3, "processes_observed": 9}, "gauges": {"uptime_s": 120}}}
    assert c.post("/api/v1/sensors/heartbeat", headers={"X-API-Key": key}, json=hb).status_code == 200
    r = c.post("/api/v1/files", headers={"X-API-Key": key}, data={"file": (io.BytesIO(fake_pe()), "t.exe"),
                                                                    "meta": json.dumps({"source": "edr", "sensor_id": "host1"})})
    shas = [r.get_json()["sha256"]]
    app.config["PROCESS"](shas[0])
    shas += [submit(app, c, key, t, n) for t, n in ((b"b", "fallback.exe"), (b"c", "disagree.exe"), (b"e", "error.exe"))]
    shas.append(add_legacy(app))
    submit(app, c, key, b"q", "queued.exe", process=False)  # left queued
    statuses = {x["sha256"]: x["status"] for x in app.config["DB"].q("SELECT sha256, status FROM files")}
    assert statuses[shas[3]] == "error" and statuses[shas[4]] == "done"
    urls = ["/", "/dashboard", "/submissions", "/submissions?verdict=malicious&sort=score", "/submissions?verdict=borderline",
            "/submissions?verdict=error", "/insights", "/insights?only=flagged", "/sensors", "/sensors/host1", "/model", "/settings",
            "/glossary", "/search?q=.exe", "/submissions?export=csv", "/submissions?export=json"]
    for sha in shas:
        urls += [f"/file/{sha}", f"/file/{sha}/print", f"/file/{sha}/json", f"/file/{sha}/csv"]
    for url in urls:
        resp = c.get(url)
        assert resp.status_code == 200, url
    legacy = c.get(f"/file/{shas[4]}").get_data(as_text=True)
    assert "Old report from the V3.2 model" in legacy
    assert c.get(f"/file/{shas[4]}/json").get_json()["risk"] == "low"  # old 0.5 score is not compared with the new threshold
    assert "stub parser failure" in c.get(f"/file/{shas[3]}/json").get_data(as_text=True)
    model = c.get("/model").get_data(as_text=True)
    assert "V10 replication" in model and "How verdicts are made" in model
    settings = c.get("/settings").get_data(as_text=True)
    assert "Binary Ninja at scan time" in settings and "SA2_BN=0" in settings
    dash = c.get("/dashboard").get_data(as_text=True)
    assert "Binary Ninja timed out" in dash and "Old V3.2 report" in dash
    rows = list(csv.DictReader(io.StringIO(c.get("/submissions?export=csv").get_data(as_text=True))))
    assert {"pe_v3_score", f"{BLEND}_score", "decision_path"} <= set(rows[0])  # columns follow the engines present
    assert "Online" in c.get("/sensors").get_data(as_text=True)
    assert c.get("/file/" + "0" * 64).status_code == 404
    assert c.get("/admin").status_code == 302 and c.get("/analyze").status_code == 302


def test_model_page_numbers_come_from_result_files(make):
    app, c, key = make(stub_scan(0.01))
    ev = {e["label"]: e for e in app_mod.evidence()}
    if "V10 replication" not in ev:
        pytest.skip("artifacts/v10/blind/replication_results.json not present")
    v10 = ev["V10 replication"]
    assert v10["rule_met"] is True and ev["V9 replication"]["rule_met"] is False and ev["V8 blind"]["rule_met"] is True
    page = c.get("/model").get_data(as_text=True)
    assert "%+.2f" % (100 * v10["delta"]) in page and "%+.2f" % (100 * v10["delta_ci"][0]) in page


def test_main_exits_cleanly_without_model(monkeypatch, capsys):
    from src.v8 import bn_live, deploy

    monkeypatch.setattr(bn_live, "restore_settings", lambda: False)

    def missing():
        raise deploy.ModelMissing("stub: no model")
    monkeypatch.setattr(scanner, "bundle", missing)
    assert app_mod.main([]) == 2
    err = capsys.readouterr().err
    assert "EMBER2024 model not available" in err or "thrember" in err  # without thrember it stops one step earlier


def test_explain_nsis_signed_reads_as_likely_false_positive():
    sigs = explain.signals({"signature": {"status": "Valid", "signer": "Example Ltd"}, "sections": [{"name": ".ndata", "entropy": 0, "raw_size": 0, "rwx": False}],
                            "imports": {"kernel32.dll": ["CreateProcessW"]}, "version_info": {"ProductName": "x"}, "aslr": True, "dep": True},
                           b"MZ...NullsoftInst...")
    assert {"signed_valid", "format_nsis"} <= {s["id"] for s in sigs}


def _real_engine_ready() -> bool:
    try:
        import thrember  # noqa: F401
    except ImportError:
        return False
    from src.v8 import deploy
    return (deploy.ROOT / deploy.EMBER_MODEL).is_file() and NOTEPAD.is_file()


@pytest.mark.skipif(not _real_engine_ready(), reason="needs thrember, the downloaded EMBER2024 model and a benign PE (notepad.exe or SA2_TEST_BENIGN_PE)")
def test_real_engine_on_benign_pe(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("SA2_BN", "0")  # never touch a running Binary Ninja from the test suite
    app = create_app(tmp_path / "dash", start_worker=False)  # real V8 bundle
    c = app.test_client()
    c.post("/login", data={"password": app.config["DB"].setting("admin_password")})
    r = c.post("/upload", data={"file": (io.BytesIO(NOTEPAD.read_bytes()), NOTEPAD.name)})
    sha = r.headers["Location"].rsplit("/", 1)[-1]
    app.config["PROCESS"](sha)
    rep = c.get(f"/file/{sha}/json").get_json()
    blend = next(e for e in rep["engines"] if e["name"] == BLEND)
    assert rep["verdict"] == "benign" and rep["engine_count"] == 2 and rep["decision_path"]["reason"] == "bn_disabled"
    assert blend["coverage"] == "uncovered" and abs(rep["probability"] - blend["r1_score"]) < 1e-9  # fallback = EMBER2024's score
    assert "EMBER2024 only" in c.get(f"/file/{sha}").get_data(as_text=True)
