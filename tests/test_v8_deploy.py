"""Deployed V8 blend engine (src/v8/deploy.py, src/v8/bn_live.py, src/v8/ember_map.py) and its scanner wiring.

No Binary Ninja, network, malware or research export needed. Tests that need EMBER2024_PE.model skip when it is absent.
"""

from __future__ import annotations

import math
import pickle
import sys
import time
from pathlib import Path

import numpy as np
import pytest

from src.v8 import bn_live, deploy

ROOT = Path(__file__).resolve().parents[1]
HAS_EMBER_MODEL = (ROOT / deploy.EMBER_MODEL).is_file()
OK_CAP = {"analysis_status": "ok", "functions": [], "imports": ["virtualprotect"], "strings": ["cmd /c del x"], "function_total": 3,
          "functions_disassembled": 3}
OK_HL = {"analysis_status": "ok", "functions": [], "function_total": 3, "n_library_named": 1, "n_sub": 2}


def logit(p: float) -> float:
    return math.log(p / (1 - p))


def sig(x: float) -> float:
    return 1 / (1 + math.exp(-x))


class StubR1:
    """EMBER2024 booster stand-in: fixed probability, contributions that add up to its logit."""

    def __init__(self, p: float):
        self.p = p

    def predict(self, x, pred_contrib=False):
        if not pred_contrib:
            return np.array([self.p])
        c = np.zeros((1, x.shape[1] + 1))
        c[0, 0], c[0, 701], c[0, -1] = 0.75, -0.25, logit(self.p) - 0.5
        return c


class StubBN:
    """Binary Ninja model stand-in (LGBMClassifier API)."""

    def __init__(self, q: float, n: int):
        self.q, self.n = q, n

    def predict_proba(self, x):
        return np.array([[1 - self.q, self.q]] * len(x))

    def predict(self, x, pred_contrib=False):
        c = np.zeros((len(x), self.n + 1))
        c[:, 0], c[:, -1] = 1.0, logit(self.q) - 1.0
        return c


def stub_bundle(p: float, q: float, *, w=0.3, t_blend=-0.91947, thr=0.31491, cols=("cap6_a", "hl6_b")) -> dict:
    cand = {"cols": list(cols), "model": StubBN(q, len(cols)), "w": w, "t_blend": t_blend, "thr_r1": thr}
    return {"tag": "v8", "candidate": cand, "cols": list(cols), "w": w, "t_blend": t_blend, "thr_r1": thr, "r1_model": StubR1(p)}


def vec() -> np.ndarray:
    v = np.zeros(2568, dtype=np.float32)
    v[2] = 1  # em_general_is_pe
    return v


# ------------------------------------------------------------------ blend math

@pytest.mark.parametrize("p,q", [(0.9, 0.8), (0.2, 0.95), (0.31, 0.01), (0.5, 0.5)])
def test_covered_margin_matches_hand_computation(p, q):
    b = stub_bundle(p, q)
    s = deploy.score_vector(b, vec(), {"cap6_a": 1.0, "hl6_b": 2.0})
    m = logit(p) + 0.3 * logit(q) - (-0.91947)
    assert s["covered"] and s["blend_margin"] == pytest.approx(m, abs=1e-9)
    assert s["decision"] == (m >= 0)
    assert s["probability"] == pytest.approx(sig(m + logit(0.31491)), abs=1e-12)
    assert s["bn_score"] == pytest.approx(q) and s["r1_score"] == pytest.approx(p)
    # display scale: one threshold for every file, monotone in the margin
    assert (s["probability"] >= 0.31491) == s["decision"] or abs(m) < 1e-12


@pytest.mark.parametrize("p", [0.05, 0.31, 0.3149, 0.32, 0.999])
def test_uncovered_falls_back_to_r1_decision(p):
    b = stub_bundle(p, 0.99)  # BN model would say malicious; it must be ignored
    s = deploy.score_vector(b, vec(), None)
    assert not s["covered"] and s["bn_score"] is None
    assert s["blend_margin"] == pytest.approx(logit(p) - logit(0.31491), abs=1e-9)
    assert s["decision"] == (p >= 0.31491)
    assert s["probability"] == pytest.approx(p, abs=1e-12)  # display score == R1's raw score


def test_contributions_sum_to_display_logit_and_names():
    for bn in ({"cap6_a": 1.0, "hl6_b": 2.0}, None):
        s = deploy.score_vector(stub_bundle(0.7, 0.2), vec(), bn)
        total = s["contrib_base"] + sum(c for _, _, c in s["contrib"])
        assert total == pytest.approx(s["blend_margin"] + s["display_shift"], abs=1e-9)
        assert total == pytest.approx(logit(s["probability"]), abs=1e-9)
        names = [n for n, _, _ in s["contrib"]]
        assert len(names) == 2568 + (2 if bn else 0)
        assert names[0] == "em_general_size" and names[701] == "em_header_coff_machine"
        parts = s["contrib_parts"]
        assert sum(parts.values()) == pytest.approx(s["contrib_base"])
        if bn:  # BN contributions are scaled by w
            assert dict((n, c) for n, _, c in s["contrib"])["cap6_a"] == pytest.approx(0.3)
            assert parts["offset"] == pytest.approx(0.91947 + logit(0.31491))


def test_frozen_candidate_bundle_decide():
    """Real candidate.pkl + frozen thresholds; R1 stubbed so the EMBER2024 model file is not needed."""
    with (ROOT / deploy.CANDIDATE).open("rb") as fh:
        cand = pickle.load(fh)
    assert cand["w"] == 0.3 and cand["t_blend"] == pytest.approx(-0.919470078742035) and cand["thr_r1"] == pytest.approx(0.31491410519549656)
    feats = {**bn_live_features(OK_CAP, OK_HL)}
    assert set(cand["cols"]) <= set(feats), "extractors must yield every frozen BN column"
    b = {"candidate": cand, "cols": cand["cols"], "w": cand["w"], "t_blend": cand["t_blend"], "thr_r1": cand["thr_r1"],
         "r1_model": StubR1(0.25)}
    s = deploy.score_vector(b, vec(), feats)
    q = float(cand["model"].predict_proba(np.array([[feats[c] for c in cand["cols"]]]))[0, 1])
    assert s["blend_margin"] == pytest.approx(logit(0.25) + 0.3 * logit(q) - cand["t_blend"], abs=1e-9)
    total = s["contrib_base"] + sum(c for _, _, c in s["contrib"])
    assert total == pytest.approx(logit(s["probability"]), abs=1e-6)
    assert not s["bn_missing_columns"]


def test_freeze_manifest_matches_shipped_models():
    bad = deploy.verify_freeze()
    assert not [b for b in bad if "/models/" in b], bad


def bn_live_features(cap: dict, hl: dict) -> dict:
    from src.v6 import bn_capabilities, bn_hlil

    return {**bn_capabilities.features_from_doc({**cap, "prep": [], "unpack": "none"}), **bn_hlil.features_from_doc(hl)}


# ------------------------------------------------------------------ Binary Ninja path selection

@pytest.fixture()
def bn_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(bn_live, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(bn_live, "WORK_DIR", tmp_path / "work")
    monkeypatch.setattr(bn_live, "LOCK_PATH", tmp_path / "bn.lock")
    monkeypatch.setattr(bn_live, "_inflight", None)  # a timed-out stub analysis of an earlier test may still be sleeping
    f = tmp_path / "sample.bin"
    f.write_bytes(b"MZ" + b"\0" * 1024)  # not a real PE: prepare() must still work (no UPX, small)
    return f


def cfg(**kw):
    return {"enabled": True, "url": "http://127.0.0.1:9/mcp", "probe_timeout": 0.5, "mode_switch": "off", "bn_exe": "", "upx": "", **kw}


def test_bn_disabled(bn_tmp):
    r = bn_live.extract(bn_tmp, "a" * 64, cfg(enabled=False))
    assert r["reason"] == "bn_disabled" and not r["covered"] and r["features"] is None


def test_bn_disabled_by_env(monkeypatch):
    monkeypatch.setenv("SA2_BN", "0")
    monkeypatch.setenv("SA2_BN_MCP_URL", "http://127.0.0.1:5555/mcp")
    c = bn_live.settings()
    assert not c["enabled"] and c["url"] == "http://127.0.0.1:5555/mcp"


def test_bn_unreachable_is_fast(bn_tmp):
    t = time.time()
    r = bn_live.extract(bn_tmp, "b" * 64, cfg())  # real probe against a closed local port
    assert r["reason"] == "bn_unreachable" and not r["covered"]
    assert time.time() - t < 3


def test_bn_stubbed_mcp_covered_then_cached(bn_tmp):
    calls = []
    passes = {"cap6": lambda c, p: calls.append("cap6") or dict(OK_CAP), "hl6": lambda c, p: calls.append("hl6") or dict(OK_HL)}
    r = bn_live.extract(bn_tmp, "c" * 64, cfg(), probe_fn=lambda u, t: True, passes=passes, connect=lambda u: object())
    assert r["covered"] and r["reason"] == "covered" and calls == ["cap6", "hl6"]
    assert r["cap6_status"] == "ok" and r["hl6_status"] == "ok" and "cap6_n_imports" in r["features"]
    r2 = bn_live.extract(bn_tmp, "c" * 64, cfg(), probe_fn=lambda u, t: False, passes=passes, connect=lambda u: object())
    assert r2["covered"] and r2["cached"] and calls == ["cap6", "hl6"]  # second scan reuses the cache


def test_bn_unusable_timeout_and_error(bn_tmp):
    up = lambda u, t: True  # noqa: E731
    r = bn_live.extract(bn_tmp, "d" * 64, cfg(), probe_fn=up, connect=lambda u: object(),
                        passes={"cap6": lambda c, p: {"analysis_status": "unsupported"}, "hl6": lambda c, p: dict(OK_HL)})
    assert r["reason"] == "bn_unusable" and r["hl6_status"] == "not_run"  # second pass skipped
    r = bn_live.extract(bn_tmp, "e" * 64, cfg(), probe_fn=up, connect=lambda u: object(),
                        passes={"cap6": lambda c, p: dict(OK_CAP), "hl6": lambda c, p: 1 / 0})
    assert r["reason"] == "bn_error" and r["cap6_status"] == "ok" and r["hl6_status"] == "error"
    r = bn_live.extract(bn_tmp, "f" * 64, cfg(), probe_fn=up, connect=lambda u: (_ for _ in ()).throw(ConnectionError("x")),
                        passes={"cap6": lambda c, p: dict(OK_CAP), "hl6": lambda c, p: dict(OK_HL)})
    assert r["reason"] == "bn_error" and not r["covered"]


def test_bn_timeout(bn_tmp, monkeypatch):
    monkeypatch.setattr("src.v6.bn_capabilities.FILE_TIMEOUT", 0.2)
    r = bn_live.extract(bn_tmp, "9" * 64, cfg(), probe_fn=lambda u, t: True, connect=lambda u: object(),
                        passes={"cap6": lambda c, p: time.sleep(1) or dict(OK_CAP), "hl6": lambda c, p: dict(OK_HL)})
    assert r["reason"] == "bn_timeout" and not r["covered"]


@pytest.fixture()
def bn_restart(bn_tmp, tmp_path, monkeypatch):
    """Windows restart mode with every process action stubbed: records kills/launches, fake APPDATA settings.json."""
    import json
    import src.ensure_bn_mcp as ebm

    appdata = tmp_path / "appdata"
    (appdata / "Binary Ninja").mkdir(parents=True)
    settings = appdata / "Binary Ninja" / "settings.json"
    original = b'{"ui.theme": "dark", "analysis.mode": "basic"}'
    settings.write_bytes(original)
    exe = tmp_path / "binaryninja.exe"
    exe.write_bytes(b"MZ")
    log = []
    monkeypatch.setenv("APPDATA", str(appdata))
    import os
    import types

    # bn_live only reads os.name and os.environ; a stand-in module keeps pathlib on the real platform
    monkeypatch.setattr(bn_live, "os", types.SimpleNamespace(name="nt", environ=os.environ))
    monkeypatch.setattr(bn_live, "_kill_bn", lambda: log.append("kill"))
    monkeypatch.setattr(bn_live.subprocess, "Popen", lambda *a, **k: log.append("launch"))
    monkeypatch.setattr(ebm, "ensure_bn_mcp", lambda *a, **k: log.append("mode=" + json.loads(settings.read_text())["analysis.mode"]))
    return {"settings": settings, "original": original, "exe": exe, "log": log, "ebm": ebm, "file": bn_tmp}


def test_bn_restart_restores_user_settings_after_both_passes(bn_restart):
    b = bn_restart
    passes = {"cap6": lambda c, p: dict(OK_CAP), "hl6": lambda c, p: dict(OK_HL)}
    r = bn_live.extract(b["file"], "7" * 64, cfg(mode_switch="restart", bn_exe=str(b["exe"])), probe_fn=lambda u, t: True,
                        passes=passes, connect=lambda u: object())
    assert r["covered"] and r["mode_enforced"]
    assert [x for x in b["log"] if x.startswith("mode=")] == ["mode=intermediate", "mode=full"]
    assert b["settings"].read_bytes() == b["original"]  # the backup was never overwritten by a modified file
    assert not (b["settings"].parent / bn_live.SETTINGS_BACKUP).exists() and b["log"][-1] == "launch"


def test_bn_restart_failure_still_restores_settings(bn_restart, monkeypatch):
    b = bn_restart

    def boom(*a, **k):
        raise RuntimeError("MCP not ready")

    monkeypatch.setattr(b["ebm"], "ensure_bn_mcp", boom)
    r = bn_live.extract(b["file"], "6" * 64, cfg(mode_switch="restart", bn_exe=str(b["exe"])), probe_fn=lambda u, t: True,
                        passes={"cap6": lambda c, p: dict(OK_CAP), "hl6": lambda c, p: dict(OK_HL)}, connect=lambda u: object())
    assert r["reason"] == "bn_error" and not r["covered"]
    assert b["settings"].read_bytes() == b["original"] and b["log"][-1] == "launch"


def test_bn_restart_skipped_when_executable_missing(bn_restart):
    b = bn_restart
    r = bn_live.extract(b["file"], "5" * 64, cfg(mode_switch="restart", bn_exe=str(b["exe"]) + ".missing"),
                        probe_fn=lambda u, t: True, passes={"cap6": lambda c, p: dict(OK_CAP), "hl6": lambda c, p: dict(OK_HL)},
                        connect=lambda u: object())
    assert r["covered"] and not r["mode_enforced"] and "not enforced" in r["note"]
    assert b["log"] == [] and b["settings"].read_bytes() == b["original"]  # running Binary Ninja never killed


# ------------------------------------------------------------------ one Binary Ninja user at a time (cross-process lock)

def test_bn_lock_two_objects_conflict_and_release(tmp_path):
    import os

    lp = tmp_path / "bn.lock"
    a, b = bn_live.BnLock(lp), bn_live.BnLock(lp)
    assert a.acquire() and not b.acquire()
    assert b.owner()["pid"] == os.getpid()
    a.release()
    a.release()  # idempotent
    assert b.acquire()
    b.release()


def test_bn_lock_stale_file_from_dead_process_does_not_block(tmp_path):
    import json

    lp = tmp_path / "bn.lock"
    lp.write_text(json.dumps({"pid": 999999, "started": 0, "host": "gone"}))  # left behind by a crashed process
    lk = bn_live.BnLock(lp)
    assert lk.acquire()
    lk.release()


def test_bn_busy_while_another_process_holds_the_lock(bn_tmp, tmp_path):
    import os
    import subprocess

    lp = tmp_path / "bn.lock"
    code = "import sys, time\nfrom src.v8.bn_live import BnLock\nprint(BnLock(sys.argv[1]).acquire(), flush=True)\ntime.sleep(60)\n"
    proc = subprocess.Popen([sys.executable, "-c", code, str(lp)], cwd=ROOT, stdout=subprocess.PIPE, text=True,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        assert proc.stdout.readline().strip() == "True"
        probed = []
        passes = {"cap6": lambda c, p: dict(OK_CAP), "hl6": lambda c, p: dict(OK_HL)}
        t = time.time()
        r = bn_live.extract(bn_tmp, "1" * 64, cfg(), probe_fn=lambda u, t: probed.append(u) or True, passes=passes,
                            connect=lambda u: object())
        assert r["reason"] == "bn_busy" and not r["covered"] and r["features"] is None
        assert f"pid {proc.pid}" in r["note"] and "R1 decision used" in r["note"]
        assert probed == [] and time.time() - t < 2  # no waiting, Binary Ninja not touched
    finally:
        proc.kill()  # the owner dies without releasing: the OS drops its lock
        proc.wait()
    r = bn_live.extract(bn_tmp, "1" * 64, cfg(), probe_fn=lambda u, t: True, passes=passes, connect=lambda u: object())
    assert r["covered"] and r["reason"] == "covered"


def test_bn_settings_backup_never_overwritten_and_restore_idempotent(bn_restart, tmp_path):
    b = bn_restart
    c = cfg(mode_switch="restart", bn_exe=str(b["exe"]))
    bak = b["settings"].parent / bn_live.SETTINGS_BACKUP
    bn_live._set_mode("intermediate", c)
    assert bak.read_bytes() == b["original"] and b"intermediate" in b["settings"].read_bytes()
    bn_live._set_mode("full", c)  # settings.json is modified now; the backup must still be the user's file
    assert bak.read_bytes() == b["original"] and b'"full"' in b["settings"].read_bytes()
    # crash between passes: nothing restored; the next start-up calls restore_settings()
    lp = tmp_path / "bn.lock"
    holder = bn_live.BnLock(lp)
    assert holder.acquire()
    assert bn_live.restore_settings(lp) is False and bak.is_file()  # another SA2 process is mid-scan: leave its files alone
    holder.release()
    assert bn_live.restore_settings(lp) is True
    assert b["settings"].read_bytes() == b["original"] and not bak.exists()
    assert bn_live.restore_settings(lp) is False and b["settings"].read_bytes() == b["original"]  # idempotent


def test_bn_busy_while_timed_out_analysis_still_running(bn_tmp, monkeypatch, tmp_path):
    import threading

    monkeypatch.setattr("src.v6.bn_capabilities.FILE_TIMEOUT", 0.2)
    gate = threading.Event()
    r = bn_live.extract(bn_tmp, "2" * 64, cfg(), probe_fn=lambda u, t: True, connect=lambda u: object(),
                        passes={"cap6": lambda c, p: gate.wait(10) and dict(OK_CAP), "hl6": lambda c, p: dict(OK_HL)})
    assert r["reason"] == "bn_timeout"
    calls = []
    passes = {"cap6": lambda c, p: calls.append(1) or dict(OK_CAP), "hl6": lambda c, p: dict(OK_HL)}
    r = bn_live.extract(bn_tmp, "3" * 64, cfg(), probe_fn=lambda u, t: True, passes=passes, connect=lambda u: object())
    assert r["reason"] == "bn_busy" and "timed out and is still running" in r["note"] and calls == []
    assert not bn_live.BnLock(tmp_path / "bn.lock").acquire()  # other processes stay out too
    gate.set()
    bn_live._inflight.result(timeout=5)
    time.sleep(0.05)
    lk = bn_live.BnLock(tmp_path / "bn.lock")
    assert lk.acquire()  # released when the timed-out call ended
    lk.release()
    r = bn_live.extract(bn_tmp, "3" * 64, cfg(), probe_fn=lambda u, t: True, passes=passes, connect=lambda u: object())
    assert r["covered"] and calls == [1]


def test_bn_connect_is_bounded(bn_tmp):
    import threading

    gate = threading.Event()
    t = time.time()
    r = bn_live.extract(bn_tmp, "4" * 64, cfg(connect_timeout=0.2), probe_fn=lambda u, t: True,
                        connect=lambda u: gate.wait(10) and object(),
                        passes={"cap6": lambda c, p: dict(OK_CAP), "hl6": lambda c, p: dict(OK_HL)})
    assert r["reason"] == "bn_timeout" and time.time() - t < 3
    r = bn_live.extract(bn_tmp, "4" * 64, cfg(), probe_fn=lambda u, t: True, connect=lambda u: object(),
                        passes={"cap6": lambda c, p: dict(OK_CAP), "hl6": lambda c, p: dict(OK_HL)})
    assert r["reason"] == "bn_busy"  # the hung connect still owns the MCP session
    gate.set()
    bn_live._inflight.result(timeout=5)
    assert bn_live.settings()["connect_timeout"] == bn_live.CONNECT_TIMEOUT


@pytest.fixture()
def mcp_stub():
    """Local HTTP server; the response depends on the path: /404, /406, /json, /sse, /junk."""
    import http.server
    import json
    import threading

    init = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05", "capabilities": {},
                                                  "serverInfo": {"name": "stub", "version": "0"}}}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            kind = self.path.strip("/")
            if kind in ("404", "406"):
                body, ctype, code = b'{"error": "nope"}', "application/json", int(kind)
            elif kind == "json":
                body, ctype, code = json.dumps(init).encode(), "application/json", 200
            elif kind == "sse":
                body, ctype, code = f"event: message\ndata: {json.dumps(init)}\n\n".encode(), "text/event-stream", 200
            else:
                body, ctype, code = b"<html>hello</html>", "text/html", 200
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_bn_probe_requires_a_real_mcp_initialize_response(mcp_stub):
    from src.ensure_bn_mcp import _mcp_probe

    assert bn_live.probe(mcp_stub + "/json", 2) and bn_live.probe(mcp_stub + "/sse", 2)
    for bad in ("/404", "/406", "/junk"):
        assert not bn_live.probe(mcp_stub + bad, 2), bad
    assert not bn_live.probe("http://127.0.0.1:9/mcp", 0.5)  # closed port
    # research probe, unchanged: urlopen raises on 4xx, so in practice it accepts any HTTP 200 body, even a non-MCP page
    assert not _mcp_probe(mcp_stub + "/404", 2) and _mcp_probe(mcp_stub + "/junk", 2)


# ------------------------------------------------------------------ EMBER2024 model file: verify / download / replace

MODEL_BYTES = b"stub EMBER2024 model bytes " * 100


@pytest.fixture()
def model_env(tmp_path, monkeypatch):
    """EMBER2024_PE.model location, URL and hash pointed at tmp_path and a local HTTP server (/good, /fail)."""
    import hashlib
    import http.server
    import threading

    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == "/good":
                self.send_response(200)
                self.send_header("Content-Length", str(len(MODEL_BYTES)))
                self.end_headers()
                self.wfile.write(MODEL_BYTES)
            else:
                self.send_response(500)
                self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    model = tmp_path / "models" / "EMBER2024_PE.model"
    monkeypatch.setattr(deploy, "EMBER_MODEL", model)
    monkeypatch.setattr(deploy, "EMBER_URL", base + "/good")
    monkeypatch.setattr(deploy, "EMBER_SHA256", hashlib.sha256(MODEL_BYTES).hexdigest())
    monkeypatch.delenv("SA2_EMBER_DOWNLOAD", raising=False)
    yield {"model": model, "base": base, "hits": hits}
    srv.shutdown()
    srv.server_close()


def test_model_missing_is_downloaded_and_verified(model_env):
    assert deploy.ensure_ember_model(quiet=True) == model_env["model"]
    assert model_env["model"].read_bytes() == MODEL_BYTES and not model_env["model"].with_name("EMBER2024_PE.model.part").exists()
    assert deploy.ensure_ember_model(quiet=True) and model_env["hits"] == ["/good"]  # later calls only verify


def test_model_download_disabled_by_env_only_verifies(model_env, monkeypatch, capsys):
    monkeypatch.setenv("SA2_EMBER_DOWNLOAD", "0")
    with pytest.raises(deploy.ModelMissing) as e:
        deploy.ensure_ember_model(quiet=True)
    assert e.value.kind == "missing" and "SA2_EMBER_DOWNLOAD=0" in str(e.value)
    assert deploy.main(["--download-model"]) == 2  # the setup step honours SA2_EMBER_DOWNLOAD=0
    assert "(missing)" in capsys.readouterr().err and model_env["hits"] == []
    model_env["model"].parent.mkdir(parents=True)
    model_env["model"].write_bytes(MODEL_BYTES)
    assert deploy.main(["--download-model"]) == 0 and model_env["hits"] == []  # present and correct: verified, no download


def test_model_wrong_hash_refused_lazily_and_replaced_by_download_model(model_env, monkeypatch, capsys):
    m = model_env["model"]
    m.parent.mkdir(parents=True)
    m.write_bytes(b"corrupt")
    with pytest.raises(deploy.ModelHashMismatch) as e:
        deploy.ensure_ember_model(quiet=True)  # dashboard start: never replaces silently
    assert e.value.kind == "wrong_hash" and "--download-model" in str(e.value) and m.read_bytes() == b"corrupt"
    monkeypatch.setenv("SA2_EMBER_DOWNLOAD", "0")
    assert deploy.main(["--download-model"]) == 2 and m.read_bytes() == b"corrupt"
    assert "(wrong hash)" in capsys.readouterr().err
    monkeypatch.delenv("SA2_EMBER_DOWNLOAD")
    assert deploy.main(["--download-model"]) == 0 and m.read_bytes() == MODEL_BYTES and model_env["hits"] == ["/good"]


def test_model_download_failures_leave_existing_file_and_no_part(model_env, monkeypatch):
    m = model_env["model"]
    monkeypatch.setattr(deploy, "EMBER_URL", model_env["base"] + "/fail")
    with pytest.raises(deploy.ModelDownloadFailed) as e:
        deploy.ensure_ember_model(quiet=True)
    assert e.value.kind == "download_failed" and "Check internet access" in str(e.value) and not m.exists()
    m.write_bytes(b"corrupt")
    with pytest.raises(deploy.ModelDownloadFailed) as e:
        deploy.ensure_ember_model(quiet=True, replace_bad=True)
    assert "left in place" in str(e.value) and m.read_bytes() == b"corrupt"
    monkeypatch.setattr(deploy, "EMBER_URL", model_env["base"] + "/good")
    monkeypatch.setattr(deploy, "EMBER_SHA256", "0" * 64)  # server sends bytes with another hash
    with pytest.raises(deploy.ModelDownloadFailed) as e:
        deploy.ensure_ember_model(quiet=True, replace_bad=True)
    assert "it was not used" in str(e.value) and m.read_bytes() == b"corrupt"
    assert not m.with_name("EMBER2024_PE.model.part").exists()


def test_ember_failure_is_carried_into_the_report(tmp_path, monkeypatch):
    from src.webscan import scanner

    def boom(raw):
        raise ValueError("bad_dim:12")

    monkeypatch.setattr(deploy, "ember_vector", boom)
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZ" + b"\0" * 200)
    assert deploy.score_file(f, {"stub": True})["error"] == "ember_failed:ValueError: bad_dim:12"
    monkeypatch.setattr(scanner, "_bundle", {"thr_r1": 0.31491410519549656})
    rep = scanner.scan(f)
    assert rep["verdict"] == "error" and rep["error"] == "ember_failed:ValueError: bad_dim:12" and rep["engines"] == []


def test_cli_reports_missing_model_without_traceback(monkeypatch, capsys):
    def missing(**k):
        raise deploy.ModelMissing("Missing EMBER2024_PE.model")

    monkeypatch.setattr(deploy, "ensure_ember_model", missing)
    assert deploy.main(["--download-model"]) == 2
    assert "EMBER2024 model not available" in capsys.readouterr().err


# ------------------------------------------------------------------ EMBER feature map

def test_ember_feature_map_layout():
    from src.v8.ember_map import ember_feature_map

    m = ember_feature_map()
    assert len(m) == 2568 and [r["index"] for r in m] == list(range(2568))
    starts = {r["group"]: r["group_offset"] for r in m}
    assert starts == {"general": 0, "histogram": 7, "byteentropy": 263, "strings": 519, "header": 696, "section": 770,
                      "imports": 994, "exports": 2276, "datadirectories": 2405, "richheader": 2439, "authenticode": 2472,
                      "pefilewarnings": 2480}
    # thrember's categorical columns (src.v4.experiment.EMBER_CATEGORICAL = 2..6, 701, 702)
    assert [m[i]["kind"] for i in (2, 3, 4, 5, 6, 701, 702)] == ["cat"] * 7
    assert m[701]["name"] == "em_header_coff_machine" and m[702]["name"] == "em_header_optional_subsystem"


# ------------------------------------------------------------------ scanner wiring (no model file needed)

def test_scanner_report_shape_with_stubbed_models(tmp_path, monkeypatch):
    from src.webscan import explain, scanner

    monkeypatch.setattr(scanner, "_bundle", stub_bundle(0.62, 0.5))
    monkeypatch.setattr(deploy, "ember_vector", lambda raw: vec())
    monkeypatch.setenv("SA2_BN_MCP_URL", "http://127.0.0.1:9/mcp")
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZ" + b"\0" * 512)
    rep = scanner.scan(f)
    assert rep["report_version"] == scanner.REPORT_VERSION >= 5
    names = [e["name"] for e in rep["engines"]]
    assert names == ["v8_blend", "ember2024"]
    for e in rep["engines"]:
        assert {"name", "model_tag", "probability", "threshold", "threshold_source", "frozen_threshold", "flagged", "recommended"} <= set(e)
    blend = rep["engines"][0]
    assert blend["coverage"] == "uncovered" and blend["fallback_reason"] == "bn_unreachable"
    assert rep["decision_path"] == {"path": "r1_fallback", "reason": "bn_unreachable", "note": rep["bn"]["note"]}
    assert rep["probability"] == pytest.approx(0.62) and rep["verdict"] == "malicious"
    assert rep["explanation"]["final_probability"] == pytest.approx(rep["probability"], abs=1e-6)
    assert set(scanner.thresholds()) == {"v8_blend", "ember2024"}
    explain.assessment(rep, rep["signals"])  # must not crash on the new feature names


def test_scanner_verdict_follows_blend_not_r1_on_covered_file(tmp_path, monkeypatch):
    from src.webscan import scanner

    monkeypatch.setattr(scanner, "_bundle", stub_bundle(0.25, 0.9))  # R1 alone: not flagged; blend margin > 0
    monkeypatch.setattr(deploy, "ember_vector", lambda raw: vec())
    monkeypatch.setattr(bn_live, "extract", lambda path, sha, cfg: {
        "covered": True, "reason": "covered", "note": "stub", "cap6_status": "ok", "hl6_status": "ok", "seconds": 0.0,
        "url": "stub", "mode_enforced": False, "prep": [], "cached": False, "features": {"cap6_a": 1.0, "hl6_b": 2.0}})
    f = tmp_path / "y.exe"
    f.write_bytes(b"MZ" + b"\0" * 512)
    rep = scanner.scan(f)
    blend, r1 = rep["engines"]
    m = logit(0.25) + 0.3 * logit(0.9) + 0.91947
    assert blend["coverage"] == "covered" and blend["blend_margin"] == pytest.approx(m)
    assert blend["flagged"] and not r1["flagged"] and rep["verdict"] == "malicious"
    assert rep["probability"] == pytest.approx(sig(m + logit(0.31491)))


# ------------------------------------------------------------------ real EMBER2024 model (skips when absent)

@pytest.mark.skipif(not HAS_EMBER_MODEL, reason="EMBER2024_PE.model not downloaded (python -m src.v8.deploy --download-model)")
def test_real_bundle_contributions_and_fallback():
    b = deploy.load_bundle(verify=True, download=False)
    s = deploy.score_vector(b, vec(), None)
    assert s["probability"] == pytest.approx(s["r1_score"], abs=1e-9)
    total = s["contrib_base"] + sum(c for _, _, c in s["contrib"])
    assert total == pytest.approx(logit(s["probability"]), abs=1e-6)
    assert abs(s["contrib_parts"]["clip_adjust"]) < 1e-6


@pytest.mark.skipif(not HAS_EMBER_MODEL or sys.platform != "win32", reason="needs EMBER2024_PE.model and a Windows python.exe")
def test_real_scan_of_python_exe_without_binary_ninja(monkeypatch):
    from src.webscan import scanner

    monkeypatch.setenv("SA2_BN", "0")
    rep = scanner.scan(Path(sys.executable))
    assert rep["verdict"] in ("benign", "malicious") and rep["decision_path"]["reason"] == "bn_disabled"
    assert rep["engines"][0]["probability"] == pytest.approx(rep["engines"][1]["probability"])
