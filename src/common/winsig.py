"""Authenticode status + signer via PowerShell (no pywin32). Path goes through an env var, never the command string."""

from __future__ import annotations

import json
import os
import re
import subprocess
from functools import lru_cache

_PS = (
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8;"
    "$s = Get-AuthenticodeSignature -LiteralPath $env:SA2_SIG_PATH;"
    "[pscustomobject]@{status = [string]$s.Status; subject = [string]$s.SignerCertificate.Subject;"
    " issuer = [string]$s.SignerCertificate.Issuer; timestamped = [bool]$s.TimeStamperCertificate} | ConvertTo-Json -Compress"
)
_CN = re.compile(r'CN=("[^"]+"|[^,]+)')


def _cn(dn: str) -> str:
    m = _CN.search(dn or "")
    return m.group(1).strip('"').strip() if m else ""


@lru_cache(maxsize=4096)
def _info(path: str, _key: tuple) -> dict:
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS],
            capture_output=True, timeout=20, env={**os.environ, "SA2_SIG_PATH": path},
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        d = json.loads(out.stdout.decode("utf-8", errors="replace").strip() or "{}")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        d = {}
    return {"status": d.get("status") or "Unknown", "signer": _cn(d.get("subject", "")),
            "issuer": _cn(d.get("issuer", "")), "timestamped": bool(d.get("timestamped"))}


def signature_info(path: str) -> dict:
    """{'status': 'Valid'|'NotSigned'|'HashMismatch'|..., 'signer': CN, 'issuer': CN, 'timestamped': bool}."""
    try:
        st = os.stat(path)
    except OSError:
        return {"status": "Unknown", "signer": "", "issuer": "", "timestamped": False}
    return _info(path, (st.st_mtime_ns, st.st_size))


def signature_status(path: str) -> str:
    return signature_info(path)["status"]


if __name__ == "__main__":
    import sys
    print(signature_info(sys.argv[1]))
