"""Scan-time Binary Ninja features (cap6_* + hl6_*) for the deployed V8 blend. Static analysis only.

Runs the frozen research extractors (src.v6.bn_capabilities.analyze in intermediate analysis mode, then
src.v6.bn_hlil.analyze in full mode) on one file through the Binary Ninja GUI MCP server, with the
research time budgets and static preparation (overlay stripping above 16 MB, `upx -d`). Extraction is
strictly sequential: one module lock inside a process, and a cross-process lock (BnLock) so that only one SA2
process (dashboard or command-line scorer) drives Binary Ninja at a time. A process that finds Binary Ninja in use
by another SA2 process, or by an earlier analysis of its own that timed out and is still running, does not wait:
that file falls back to R1 with reason bn_busy.

Whenever Binary Ninja is disabled, unreachable, times out or yields unusable features, the caller falls
back to R1's own decision, exactly as the frozen protocol does for uncovered files.

Environment:
  SA2_BN=0                       disable Binary Ninja (always R1 fallback)
  SA2_BN_MCP_URL=<url>           MCP endpoint (default http://127.0.0.1:24642/mcp)
  SA2_BN_PROBE_TIMEOUT=<sec>     reachability probe timeout (default 1.0)
  SA2_BN_CONNECT_TIMEOUT=<sec>   MCP session set-up timeout per pass (default 30)
  SA2_BN_LOCK=<path>             cross-process lock file (default <temp>/sa2scan_bn.lock, per user on Windows)
  SA2_BN_MODE_SWITCH=restart|off restart  = enforce the research analysis modes the way the research did
                                            (rewrite %APPDATA%/Binary Ninja/settings.json and restart
                                            Binary Ninja before each pass, restore and relaunch after);
                                 off      = use whatever mode the running Binary Ninja is in (deviation,
                                            recorded in the report)
  SA2_BN_EXE=<path>              binaryninja.exe (default: per-user install path used by the research)
  SA2_UPX=<path>                 upx.exe (default tools/upx/upx-4.2.4-win64/upx.exe, then PATH)
"""

from __future__ import annotations

import json
import os
import os as _os  # the lock and file writes use the real module even where tests stand in for bn_live.os
import platform
import shutil
import subprocess
import tempfile
import threading
import time
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FuturesTimeout
from pathlib import Path
from typing import Any, Callable

try:  # OS file locks: released by the OS when the owning process exits or crashes
    import msvcrt
    fcntl = None
except ImportError:  # POSIX
    msvcrt = None
    import fcntl

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_URL = "http://127.0.0.1:24642/mcp"
USABLE = ("ok", "partial")  # same as src.v7.experiment.USABLE
CACHE_DIR = ROOT / "artifacts" / "dashboard" / "bn_cache"
WORK_DIR = ROOT / "artifacts" / "dashboard" / "bn_work"
SETTINGS_BACKUP = "settings.json.sa2scan_backup"
LOCK_NAME = "sa2scan_bn.lock"
LOCK_PATH: Path | None = None  # injection point (tests); else SA2_BN_LOCK, else <temp>/sa2scan_bn.lock
CONNECT_TIMEOUT = 30.0
_lock = threading.Lock()
_inflight: Future | None = None  # a timed-out connect/analysis of this process that is still running against Binary Ninja


def _float(v: str | None, default: float) -> float:
    try:
        return float(v) if v else default
    except ValueError:
        return default


def settings() -> dict[str, Any]:
    env = os.environ
    return {
        "enabled": env.get("SA2_BN", "1").strip().lower() not in ("0", "off", "false", "no", "disabled"),
        "url": env.get("SA2_BN_MCP_URL", DEFAULT_URL).strip() or DEFAULT_URL,
        "probe_timeout": _float(env.get("SA2_BN_PROBE_TIMEOUT"), 1.0),
        "connect_timeout": _float(env.get("SA2_BN_CONNECT_TIMEOUT"), CONNECT_TIMEOUT),
        "mode_switch": env.get("SA2_BN_MODE_SWITCH", "restart").strip().lower() or "restart",
        "bn_exe": env.get("SA2_BN_EXE", ""),
        "upx": env.get("SA2_UPX", ""),
    }


def _read_rpc(resp: Any, limit: int = 65536) -> Any:
    """First JSON-RPC message of an MCP HTTP response (plain JSON or server-sent events), reading at most limit bytes."""
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "text/event-stream" in ctype:  # the stream may stay open: stop at the first data line
        n = 0
        while n < limit:
            line = resp.readline(limit)
            if not line:
                return None
            n += len(line)
            t = line.decode("utf-8", "replace").strip()
            if t.startswith("data:") and t[5:].strip():
                return json.loads(t[5:].strip())
        return None
    raw = resp.read(limit).decode("utf-8", "replace").strip()
    if raw.startswith(("event:", "data:")):
        for t in raw.splitlines():
            if t.startswith("data:") and t[5:].strip():
                return json.loads(t[5:].strip())
        return None
    return json.loads(raw) if raw else None


def probe(url: str, timeout: float) -> bool:
    """True only for a real MCP initialize response: HTTP 200 whose JSON-RPC body (JSON or SSE) has a result with
    protocolVersion or serverInfo. Any other status (including 4xx), body, or network error is False, and a closed port
    fails immediately. Stricter than src.ensure_bn_mcp._mcp_probe (any HTTP 200-499), which the research scripts keep."""
    import http.client
    import urllib.error
    import urllib.request

    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                     "clientInfo": {"name": "sa2-scan-probe", "version": "1"}}}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST",
                                 headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return False
            body = _read_rpc(resp)
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
        return False  # HTTPError (4xx/5xx) is a URLError
    res = body.get("result") if isinstance(body, dict) else None
    return isinstance(res, dict) and ("protocolVersion" in res or "serverInfo" in res)


# ------------------------------------------------------------------ one Binary Ninja user at a time

def lock_path() -> Path:
    if LOCK_PATH is not None:
        return Path(LOCK_PATH)
    env = os.environ.get("SA2_BN_LOCK", "").strip()
    return Path(env) if env else Path(tempfile.gettempdir()) / LOCK_NAME


class BnLock:
    """Cross-process, non-blocking lock for using Binary Ninja (dashboards and the command-line scorer).

    An OS lock on one byte of a lock file: msvcrt.locking on Windows, fcntl.flock elsewhere. The OS drops it when the
    owning process exits or crashes, so a lock left behind by a dead process never blocks anyone and nothing has to be
    deleted; a lock held by a live process is never broken, because that process may still be driving Binary Ninja.
    The file records the owner's pid and start time for messages. Two BnLock objects conflict even inside one process.
    """

    _OFFSET = 1 << 20  # Windows byte-range locks also block reads: lock a byte beyond the owner record

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else lock_path()
        self._fd: int | None = None

    def acquire(self) -> bool:
        if self._fd is not None:
            raise RuntimeError("BnLock is not re-entrant")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = _os.open(str(self.path), _os.O_RDWR | _os.O_CREAT, 0o644)
        try:
            if msvcrt is not None:
                _os.lseek(fd, self._OFFSET, 0)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            _os.close(fd)
            return False
        try:
            rec = json.dumps({"pid": _os.getpid(), "started": time.time(), "host": platform.node()}).encode("utf-8")
            _os.lseek(fd, 0, 0)
            _os.write(fd, rec)
            _os.ftruncate(fd, len(rec))
        except OSError:
            pass  # the record is informational only
        self._fd = fd
        return True

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            try:
                _os.ftruncate(fd, 0)
            except OSError:
                pass
            if msvcrt is not None:
                _os.lseek(fd, self._OFFSET, 0)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            _os.close(fd)  # closing the handle releases the lock in any case

    @property
    def held(self) -> bool:
        return self._fd is not None

    def owner(self) -> dict[str, Any] | None:
        """{"pid", "started", "host"} written by the current holder, if readable."""
        try:
            with open(self.path, "rb") as fh:
                return json.loads(fh.read(4096).decode("utf-8") or "null")
        except (OSError, ValueError):
            return None


def _inflight_alive() -> bool:
    return _inflight is not None and not _inflight.done()


def _upx_exe(cfg: dict[str, Any]) -> str | None:
    from src.v6.unpack import UPX_EXE

    for cand in (cfg.get("upx"), str(ROOT / UPX_EXE)):
        if cand and Path(cand).is_file():
            return cand
    return shutil.which("upx")


def prepare(path: Path, sha256: str, work: Path, cfg: dict[str, Any]) -> tuple[Path, list[str]]:
    """src.v6.unpack.prepare with output in a per-scan work folder and a configurable upx path.

    Returns (target, prep) where prep uses the research tokens: overlay_stripped, too_large, upx, upx_failed.
    """
    from src.v4.bn_extract import MAX_BYTES
    from src.v6.unpack import image_end, is_upx

    target, prep = path, []
    if path.stat().st_size > MAX_BYTES:
        end = image_end(path)
        if end is None or end <= 0 or end > MAX_BYTES:
            return path, ["too_large"]
        target = work / f"{sha256}.img"
        with open(path, "rb") as src:
            target.write_bytes(src.read(end))
        prep.append("overlay_stripped")
    if is_upx(target):
        exe, out = _upx_exe(cfg), work / f"{sha256}.bin"
        ok = False
        if exe:
            try:  # upx -d decompresses from the file format; the sample is never run
                r = subprocess.run([exe, "-d", "-q", "-o", str(out), str(target)], capture_output=True, timeout=60)
                ok = r.returncode == 0 and out.is_file()
            except (subprocess.TimeoutExpired, OSError):
                ok = False
        if ok:
            target = out
        prep.append("upx" if ok else "upx_failed")
    return target, prep


# ------------------------------------------------------------------ Binary Ninja analysis mode

def _bn_dir() -> Path:
    return Path(os.environ.get("APPDATA", str(Path.home()))) / "Binary Ninja"


def _bn_exe(cfg: dict[str, Any]) -> Path:
    from src.ensure_bn_mcp import DEFAULT_BN

    return Path(cfg["bn_exe"]) if cfg.get("bn_exe") else DEFAULT_BN


def _kill_bn() -> None:
    subprocess.run(["taskkill", "/IM", "binaryninja.exe", "/F"], capture_output=True)
    time.sleep(4)


# Invariant that makes the sequence crash-safe: settings.json differs from the user's own file only while the backup
# exists. _set_mode writes the backup (from the user's file) before it modifies settings.json, and never rewrites an
# existing backup; restore copies the backup back first and removes it last. Both writes are atomic (temp + replace).
# Only the BnLock holder runs this sequence.

def _atomic_write(p: Path, data: bytes) -> None:
    tmp = p.with_name(p.name + ".sa2scan_tmp")
    tmp.write_bytes(data)
    tmp.replace(p)


def _restore_settings_file() -> bool:
    """Copy the backup back over settings.json, then remove it. Idempotent; the caller holds BnLock."""
    d = _bn_dir()
    bak = d / SETTINGS_BACKUP
    if not bak.is_file():
        return False
    _atomic_write(d / "settings.json", bak.read_bytes())
    bak.unlink()
    return True


def restore_settings(lock: Path | str | None = None) -> bool:
    """Put back the user's Binary Ninja settings if an earlier scan was interrupted (crash between passes). True if
    restored. Does nothing while another SA2 process holds the Binary Ninja lock: that process restores them itself."""
    if not (_bn_dir() / SETTINGS_BACKUP).is_file():
        return False
    lk = BnLock(lock)
    if not lk.acquire():
        return False
    try:
        return _restore_settings_file()
    finally:
        lk.release()


def _set_mode(mode: str, cfg: dict[str, Any]) -> None:
    """Research src.v10.chain.set_mode equivalent: kill Binary Ninja, set analysis.mode, relaunch, wait for MCP."""
    from src.ensure_bn_mcp import ensure_bn_mcp

    d = _bn_dir()
    cur, bak = d / "settings.json", d / SETTINGS_BACKUP
    _kill_bn()
    d.mkdir(parents=True, exist_ok=True)
    if not bak.is_file():  # no backup => settings.json is the user's own file (invariant above)
        _atomic_write(bak, cur.read_bytes() if cur.is_file() else b"{}")
    try:
        body = json.loads(bak.read_text(encoding="utf-8") or "{}")
    except ValueError as e:
        raise RuntimeError(f"cannot parse Binary Ninja settings.json: {e}") from e
    body["analysis.mode"] = mode
    _atomic_write(cur, json.dumps(body, indent=4).encode("utf-8"))
    ensure_bn_mcp(cfg["url"], _bn_exe(cfg), wait_seconds=180, restart_if_stuck=True)


def _restore_mode(cfg: dict[str, Any]) -> None:
    _kill_bn()
    _restore_settings_file()
    exe = _bn_exe(cfg)
    if exe.is_file():  # leave Binary Ninja running with the user's own settings, as it was found
        subprocess.Popen([str(exe)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ------------------------------------------------------------------ extraction

def _connect(url: str) -> Any:
    from src.bn_mcp import BnMcpClient

    client = BnMcpClient(url)
    client.connect()
    return client


def _bounded(fn: Callable[..., Any], timeout: float, *args: Any) -> Any:
    """fn(*args) in a daemon thread, waiting at most timeout seconds. A call that times out keeps running (a thread cannot
    be stopped); it is recorded in _inflight so this process starts no other Binary Ninja work until it ends."""
    global _inflight
    fut: Future = Future()

    def run() -> None:
        if not fut.set_running_or_notify_cancel():
            return
        try:
            fut.set_result(fn(*args))
        except BaseException as e:  # noqa: BLE001 (handed to the waiting caller)
            fut.set_exception(e)

    threading.Thread(target=run, name="sa2-bn", daemon=True).start()
    try:
        return fut.result(timeout=timeout)
    except FuturesTimeout:
        _inflight = fut
        raise


def _run_pass(analyze: Callable[[Any, Path], dict[str, Any]], target: Path, url: str, file_timeout: float,
              mode_switch: bool, cfg: dict[str, Any], connect: Callable[[str], Any] = _connect) -> dict[str, Any]:
    from src.ensure_bn_mcp import reboot_bn_mcp
    from src.v4.bn_extract import FileTimeout

    ct = float(cfg.get("connect_timeout") or CONNECT_TIMEOUT)
    try:
        client = _bounded(connect, ct, url)
    except FuturesTimeout:
        return {"analysis_status": "error", "errors": [f"connect: timeout after {ct:g} s"]}
    except Exception as e:
        return {"analysis_status": "error", "errors": [f"connect: {type(e).__name__}: {str(e)[:200]}"]}
    try:
        return _bounded(analyze, file_timeout, client, target)
    except (FuturesTimeout, FileTimeout) as e:
        if mode_switch:  # research behaviour after a timeout; only when this scanner owns Binary Ninja restarts
            try:
                reboot_bn_mcp(url, _bn_exe(cfg))
            except Exception:
                pass
        return {"analysis_status": "error", "errors": [f"timeout:{type(e).__name__}"]}
    except Exception as e:  # MCP/tool failure: the research retried later; here the file falls back to R1
        return {"analysis_status": "error", "errors": [f"{type(e).__name__}: {str(e)[:200]}"]}


def _cache_get(kind: str, sha: str) -> dict[str, Any] | None:
    p = CACHE_DIR / kind / f"{sha}.json"
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return doc if doc.get("analysis_status") in USABLE else None


def _cache_put(kind: str, sha: str, doc: dict[str, Any]) -> None:
    if doc.get("analysis_status") not in USABLE:
        return
    d = CACHE_DIR / kind
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / f"{sha}.json.tmp"
    tmp.write_text(json.dumps(doc), encoding="utf-8")
    tmp.replace(d / f"{sha}.json")


def _result(reason: str, note: str, t0: float, **kw: Any) -> dict[str, Any]:
    out = {"covered": False, "reason": reason, "note": note, "cap6_status": kw.pop("cap6_status", "not_run"),
           "hl6_status": kw.pop("hl6_status", "not_run"), "features": None, "seconds": round(time.time() - t0, 2)}
    out.update(kw)
    return out


BUSY_INFLIGHT = ("An earlier Binary Ninja analysis in this process timed out and is still running; this file was not sent to "
                 "Binary Ninja (no overlapping analyses). R1 decision used.")


def _busy_other(lk: BnLock) -> str:
    o = lk.owner() or {}
    who = f"another SA2 process (pid {o['pid']})" if isinstance(o.get("pid"), int) else "another SA2 process"
    return (f"Binary Ninja is in use by {who}; this file was not sent to Binary Ninja (only one process may use it at a "
            "time). R1 decision used.")


def extract(path: Path, sha256: str, cfg: dict[str, Any] | None = None, *, probe_fn: Callable[[str, float], bool] | None = None,
            passes: dict[str, Callable[..., dict[str, Any]]] | None = None,
            connect: Callable[[str], Any] = _connect) -> dict[str, Any]:
    """Binary Ninja features for one file, or the reason they are unavailable.

    Returns {"covered", "reason", "note", "cap6_status", "hl6_status", "features" (cap6_*/hl6_* dict or None),
             "seconds", "url", "mode_enforced", "prep", "cached"}.
    reason: covered | bn_disabled | bn_busy | bn_unreachable | bn_too_large | bn_timeout | bn_error | bn_unusable
      bn_busy: another SA2 process holds the Binary Ninja lock, or a timed-out analysis of this process is still
               running; the file is not sent to Binary Ninja and R1 decides (no waiting).
    probe_fn / passes / connect are injection points for tests; the lock file comes from lock_path().
    """
    from src.v6 import bn_capabilities, bn_hlil

    cfg = cfg or settings()
    t0 = time.time()
    base = {"url": cfg["url"], "mode_enforced": False, "prep": [], "cached": False}
    if not cfg["enabled"]:
        return _result("bn_disabled", "Binary Ninja disabled (SA2_BN=0); R1 decision used.", t0, **base)
    cap, hl = _cache_get("cap6", sha256), _cache_get("hl6", sha256)
    if cap is None or hl is None:
        passes = passes or {"cap6": bn_capabilities.analyze, "hl6": bn_hlil.analyze}
        # Enforcing the research analysis modes kills and relaunches Binary Ninja, so it needs the executable: without it a
        # running Binary Ninja (e.g. installed elsewhere and SA2_BN_EXE unset) would be killed and never come back.
        mode_switch = cfg["mode_switch"] == "restart" and os.name == "nt" and _bn_exe(cfg).is_file()
        with _lock:
            if _inflight_alive():
                return _result("bn_busy", BUSY_INFLIGHT, t0, **base)
            xlock = BnLock()
            if not xlock.acquire():
                return _result("bn_busy", _busy_other(xlock), t0, **base)
            try:
                if not (probe_fn or probe)(cfg["url"], cfg["probe_timeout"]):
                    return _result("bn_unreachable", f"Binary Ninja MCP not reachable at {cfg['url']}; R1 decision used.", t0, **base)
                doc = _extract_locked(path, sha256, cfg, passes, connect, mode_switch, base, t0, cap, hl)
                if isinstance(doc, dict) and "covered" in doc:
                    return doc
                cap, hl = doc
            finally:
                fut = _inflight
                if fut is not None and not fut.done():  # keep other processes out until the timed-out call ends
                    fut.add_done_callback(lambda _f: xlock.release())
                else:
                    xlock.release()
    else:
        base["cached"] = True
    return _finish(cap, hl, base, t0)


def _extract_locked(path: Path, sha256: str, cfg: dict[str, Any], passes: dict[str, Callable[..., dict[str, Any]]],
                    connect: Callable[[str], Any], mode_switch: bool, base: dict[str, Any], t0: float,
                    cap: dict[str, Any] | None, hl: dict[str, Any] | None) -> Any:
    """The passes still missing from the cache, run by the BnLock holder. Returns (cap, hl), or a finished _result dict."""
    from src.v6 import bn_capabilities, bn_hlil

    touched = False  # settings.json may have been changed (set before _set_mode so a failed restart is still undone)
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=WORK_DIR) as work:
        target, prep = prepare(path, sha256, Path(work), cfg)
        base["prep"] = prep
        if prep == ["too_large"]:
            return _result("bn_too_large", "PE image over 16 MB after overlay stripping; Binary Ninja skipped as in the "
                           "research; R1 decision used.", t0, cap6_status="skipped", hl6_status="skipped", **base)
        try:
            for kind, mode, timeout in (("cap6", "intermediate", bn_capabilities.FILE_TIMEOUT),
                                        ("hl6", "full", bn_hlil.FILE_TIMEOUT)):
                if (cap if kind == "cap6" else hl) is not None:
                    continue
                if mode_switch:
                    touched = True
                    _set_mode(mode, cfg)
                    base["mode_enforced"] = True
                doc = _run_pass(passes[kind], target, cfg["url"], timeout, mode_switch, cfg, connect)
                doc.update({"sha256": sha256, "prep": prep, "wall_seconds": round(time.time() - t0, 2)})
                if kind == "cap6":
                    doc.update({"unpack": "upx" if "upx" in prep else "none", "extractor_version": bn_capabilities.EXTRACTOR_VERSION})
                    cap = doc
                else:
                    doc["extractor_version"] = bn_hlil.EXTRACTOR_VERSION
                    hl = doc
                _cache_put(kind, sha256, doc)
                if doc.get("analysis_status") not in USABLE:
                    break  # the blend needs both sets; do not spend the second pass
        except Exception as e:
            return _result("bn_error", f"Binary Ninja extraction failed ({type(e).__name__}: {str(e)[:160]}); R1 decision used.",
                           t0, cap6_status=(cap or {}).get("analysis_status", "error"),
                           hl6_status=(hl or {}).get("analysis_status", "not_run"), **base)
        finally:
            if mode_switch and touched:
                try:
                    _restore_mode(cfg)
                except Exception:
                    pass
    return cap, hl


def _finish(cap: dict[str, Any] | None, hl: dict[str, Any] | None, base: dict[str, Any], t0: float) -> dict[str, Any]:
    from src.v6 import bn_capabilities, bn_hlil

    cs = (cap or {}).get("analysis_status", "not_run")
    hs = (hl or {}).get("analysis_status", "not_run")
    if cs in USABLE and hs in USABLE:
        feats = {**bn_capabilities.features_from_doc(cap), **bn_hlil.features_from_doc(hl)}
        note = "Binary Ninja features extracted" + (" (cached)" if base["cached"] else "") + "; V8 blend decision used."
        if not base["mode_enforced"] and not base["cached"]:
            note += " Analysis mode was not enforced (SA2_BN_MODE_SWITCH=off, not Windows, or binaryninja.exe not found)."
        out = _result("covered", note, t0, cap6_status=cs, hl6_status=hs, **base)
        out.update(covered=True, features=feats)
        return out
    errs = " ".join(str(e) for d in (cap, hl) if d for e in d.get("errors", []))
    reason = "bn_timeout" if "timeout" in errs else ("bn_error" if "error" in (cs, hs) else "bn_unusable")
    return _result(reason, f"Binary Ninja features unusable (cap6={cs}, hl6={hs}); R1 decision used.", t0,
                   cap6_status=cs, hl6_status=hs, **base)
