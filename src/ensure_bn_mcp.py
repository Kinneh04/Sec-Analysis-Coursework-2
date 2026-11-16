"""Ensure Binary Ninja GUI is running and MCP HTTP endpoint responds."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


DEFAULT_BN = Path.home() / "AppData/Local/Programs/Vector35/BinaryNinja/binaryninja.exe"


def _mcp_probe(url: str, timeout: float = 5.0) -> bool:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "sa2", "version": "1"},
            },
        }
    ).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 500
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _bn_running() -> bool:
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "(Get-Process -Name binaryninja -ErrorAction SilentlyContinue).Count"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return out.stdout.strip() not in ("", "0")
    except (subprocess.SubprocessError, OSError):
        return False


def _start_bn(exe: Path) -> None:
    subprocess.Popen([str(exe)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(12)


def _restart_bn(exe: Path) -> None:
    subprocess.run(
        ["taskkill", "/IM", "binaryninja.exe", "/F"],
        capture_output=True,
        check=False,
    )
    time.sleep(4)
    _start_bn(exe)


def reboot_bn_mcp(
    mcp_url: str = "http://127.0.0.1:24642/mcp",
    bn_exe: Path | None = None,
    wait_seconds: int = 240,
) -> None:
    """Force-kill Binary Ninja, relaunch, and wait until MCP responds."""
    exe = bn_exe or DEFAULT_BN
    if not exe.is_file():
        raise FileNotFoundError(f"Binary Ninja not found: {exe}")
    print("Rebooting Binary Ninja (taskkill + relaunch)...", flush=True)
    _restart_bn(exe)
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        if _mcp_probe(mcp_url):
            print(f"MCP ready after reboot: {mcp_url}", flush=True)
            return
        time.sleep(3)
    raise RuntimeError(f"MCP not ready after BN reboot ({wait_seconds}s): {mcp_url}")


def ensure_bn_mcp(
    mcp_url: str = "http://127.0.0.1:24642/mcp",
    bn_exe: Path | None = None,
    wait_seconds: int = 180,
    restart_if_stuck: bool = True,
) -> None:
    exe = bn_exe or DEFAULT_BN
    if _mcp_probe(mcp_url):
        return
    if not exe.is_file():
        raise FileNotFoundError(f"Binary Ninja not found: {exe}")

    if not _bn_running():
        _start_bn(exe)

    deadline = time.time() + wait_seconds
    restart_after = time.time() + min(90, wait_seconds // 2)
    restarted = False
    while time.time() < deadline:
        if _mcp_probe(mcp_url):
            return
        if restart_if_stuck and not restarted and time.time() >= restart_after and _bn_running():
            _restart_bn(exe)
            restarted = True
            restart_after = time.time() + 1e9
        time.sleep(3)
    raise RuntimeError(
        f"MCP not ready at {mcp_url} after {wait_seconds}s. "
        "Ensure Binary Ninja is open and Cursor MCP integration is enabled."
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:24642/mcp")
    ap.add_argument("--wait", type=int, default=180)
    ap.add_argument("--bn-exe", default=str(DEFAULT_BN))
    ap.add_argument("--reboot", action="store_true", help="Force kill and restart BN")
    args = ap.parse_args()
    if args.reboot:
        reboot_bn_mcp(args.url, Path(args.bn_exe), args.wait)
    else:
        ensure_bn_mcp(args.url, Path(args.bn_exe), args.wait)
    print(f"MCP ready: {args.url}")


if __name__ == "__main__":
    main()
