"""Pure detection rules for SA2 Sentinel. No I/O except read_motw (reads an NTFS alternate data stream)."""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

RULES = ("user_writable", "motw_internet", "unsigned", "nonstd_port", "watchlist")
WEIGHTS = {"user_writable": 1, "motw_internet": 1, "unsigned": 1, "nonstd_port": 1, "watchlist": 2}
CANDIDATE_SCORE = 2  # rules mode: e.g. unsigned + user_writable, or any watchlist hit
STANDARD_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 3478, 5228, 8080, 8443}
SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.expandvars(p.strip().strip('"'))))


def parse_motw(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"zone": None, "host_url": None, "referrer_url": None}
    for line in text.splitlines():
        k, _, v = line.partition("=")
        k = k.strip().lower()
        if k == "zoneid":
            try:
                out["zone"] = int(v.strip())
            except ValueError:
                pass
        elif k == "hosturl":
            out["host_url"] = v.strip()
        elif k == "referrerurl":
            out["referrer_url"] = v.strip()
    return out


def read_motw(path: str) -> dict[str, Any] | None:
    try:
        with open(path + ":Zone.Identifier", encoding="utf-8", errors="replace") as fh:
            return parse_motw(fh.read(4096))
    except OSError:
        return None


def trusted_path(path: str) -> bool:
    # ponytail: path-only trust for OS / Program Files binaries (writing there needs admin); add signature check if that matters
    p = _norm(path)
    roots = [os.environ.get(k) for k in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")]
    return any(r and p.startswith(_norm(r) + os.sep) for r in roots)


def user_writable(path: str) -> bool:
    p = _norm(path)
    roots = [os.environ.get(k) for k in ("USERPROFILE", "TEMP", "TMP", "ProgramData", "PUBLIC")]
    return any(r and p.startswith(_norm(r) + os.sep) for r in roots)


def nonstd_remote(ip: str, port: int) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global and port not in STANDARD_PORTS
    except ValueError:
        return False


def parse_list(text: str) -> tuple[set[str], set[str]]:
    """Lines of sha256 or file paths (comments with #). Returns (shas, normalised paths)."""
    shas, paths = set(), set()
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        (shas.add(line.lower()) if SHA_RE.match(line) else paths.add(_norm(line)))
    return shas, paths


def on_list(sha: str | None, path: str | None, text: str) -> bool:
    shas, paths = parse_list(text)
    return bool((sha and sha.lower() in shas) or (path and _norm(path) in paths))


def list_paths(text: str) -> list[str]:
    """Path entries as written (env vars expanded, original case kept for display)."""
    out = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip().strip('"')
        if line and not SHA_RE.match(line):
            out.append(os.path.normpath(os.path.expandvars(line)))
    return out


def evaluate(f: dict[str, Any], enabled: set[str], watchlist: str = "") -> list[str]:
    """f: {path, sha256, signature, motw, remote:[(ip, port)]} → names of rules that fired."""
    hits = []
    if f.get("path") and user_writable(f["path"]):
        hits.append("user_writable")
    if (f.get("motw") or {}).get("zone") is not None and f["motw"]["zone"] >= 3:
        hits.append("motw_internet")
    if f.get("signature") and f["signature"] != "Valid":
        hits.append("unsigned")
    if any(nonstd_remote(ip, port) for ip, port in f.get("remote") or []):
        hits.append("nonstd_port")
    if on_list(f.get("sha256"), f.get("path"), watchlist):
        hits.append("watchlist")
    return [h for h in hits if h in enabled]


def score(hits: list[str]) -> int:
    return sum(WEIGHTS.get(h, 0) for h in hits)
