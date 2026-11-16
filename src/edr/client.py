"""stdlib HTTP client for the SA2 Scan API (ping, heartbeat, lookup, upload)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from typing import Any


class Client:
    def __init__(self, base_url: str, api_key: str, timeout: float = 15):
        self.base = base_url.rstrip("/")
        self.key = api_key
        self.timeout = timeout

    def _req(self, method: str, path: str, body: bytes | None = None, ctype: str | None = None) -> tuple[int, Any]:
        """Returns (http_status, json_or_None). Raises OSError/URLError when unreachable."""
        req = urllib.request.Request(self.base + path, data=body, method=method, headers={"X-API-Key": self.key})
        if ctype:
            req.add_header("Content-Type", ctype)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        try:
            return status, json.loads(raw or b"null")
        except json.JSONDecodeError:
            return status, None

    def ping(self) -> tuple[int, Any, float]:
        t = time.perf_counter()
        st, js = self._req("GET", "/api/v1/ping")
        return st, js, round((time.perf_counter() - t) * 1000, 1)

    def heartbeat(self, payload: dict[str, Any]) -> int:
        return self._req("POST", "/api/v1/sensors/heartbeat", json.dumps(payload, default=str).encode(), "application/json")[0]

    def lookup(self, sha256: str) -> tuple[int, Any]:
        return self._req("GET", f"/api/v1/files/{sha256}")

    def upload(self, filename: str, data: bytes, meta: dict[str, Any]) -> tuple[int, Any]:
        b = uuid.uuid4().hex
        safe = filename.replace('"', "_").replace("\r", "_").replace("\n", "_")
        body = b"".join([
            f'--{b}\r\nContent-Disposition: form-data; name="meta"\r\nContent-Type: application/json\r\n\r\n'.encode(),
            json.dumps(meta, default=str).encode(), b"\r\n",
            f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{safe}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n".encode(),
            data, f"\r\n--{b}--\r\n".encode(),
        ])
        return self._req("POST", "/api/v1/files", body, f"multipart/form-data; boundary={b}")
