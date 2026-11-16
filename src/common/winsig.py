"""Authenticode status via PowerShell (no pywin32). Path goes through an env var, never the command string."""

from __future__ import annotations

import os
import subprocess
from functools import lru_cache


@lru_cache(maxsize=4096)
def _status(path: str, _key: tuple) -> str:
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "(Get-AuthenticodeSignature -LiteralPath $env:SA2_SIG_PATH).Status"],
            capture_output=True, text=True, timeout=20,
            env={**os.environ, "SA2_SIG_PATH": path},
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return out.stdout.strip() or "Unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "Unknown"


def signature_status(path: str) -> str:
    """'Valid', 'NotSigned', 'HashMismatch', ... or 'Unknown'. Cached per (path, mtime, size)."""
    try:
        st = os.stat(path)
    except OSError:
        return "Unknown"
    return _status(path, (st.st_mtime_ns, st.st_size))
