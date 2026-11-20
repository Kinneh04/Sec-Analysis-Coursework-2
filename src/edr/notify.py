"""Windows toast notification (bottom-right). Clicking it opens `url` in the default browser.

Uses PowerShell's built-in WinRT toast API: no extra packages. Text is passed through environment variables, never
interpolated into the script, so file names cannot inject commands.
"""

from __future__ import annotations

import base64
import os
import subprocess
import threading

_PS = r"""
$ErrorActionPreference = 'Stop'
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
function E($s) { [System.Security.SecurityElement]::Escape($s) }
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml("<toast activationType='protocol' launch='$(E $env:SA2_URL)'><visual><binding template='ToastGeneric'><text>$(E $env:SA2_TITLE)</text><text>$(E $env:SA2_MSG)</text></binding></visual></toast>")
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($x))
"""
_ENC = base64.b64encode(_PS.encode("utf-16-le")).decode()


def toast(title: str, message: str, url: str) -> bool:
    """Fire-and-forget. Returns False when not on Windows or the URL is not http(s)."""
    if os.name != "nt" or not url.startswith(("http://", "https://")):
        return False
    env = {**os.environ, "SA2_TITLE": title[:100], "SA2_MSG": message[:200], "SA2_URL": url}

    def run() -> None:
        try:
            r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
                                "-EncodedCommand", _ENC], env=env, capture_output=True, text=True, timeout=60, creationflags=0x08000000)  # CREATE_NO_WINDOW
            if r.returncode:
                print(f"[sentinel] notification failed: {r.stderr.strip()[:300]}", flush=True)
        except (OSError, subprocess.SubprocessError) as e:
            print(f"[sentinel] notification failed: {e}", flush=True)

    threading.Thread(target=run, daemon=True).start()
    return True
