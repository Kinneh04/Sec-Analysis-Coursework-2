"""Finds PE files offered by local HTTP servers (e.g. `python -m http.server`) so Sentinel can scan them.

Sentinel does not sniff packets. It notices a local process that is serving HTTP, reads the directory listing, and
downloads each .exe/.dll/... it finds exactly as a browser would. Files are saved to a cache folder, never executed.
"""

from __future__ import annotations

import hashlib
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

PE_EXT = (".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl")
SERVER_CMD = ("http.server", "simplehttpserver")


class _Hrefs(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.hrefs += [v for k, v in attrs if k == "href" and v]


def is_http_server(cmdline: list[str]) -> bool:
    return any(s in " ".join(cmdline).lower() for s in SERVER_CMD)


def base_url(ip: str, port: int) -> str:
    host = "127.0.0.1" if ip in ("0.0.0.0", "", "::") else f"[{ip}]" if ":" in ip else ip
    return f"http://{host}:{port}/"


def _get(url: str, timeout: float, method: str = "GET"):
    return urllib.request.urlopen(urllib.request.Request(url, method=method), timeout=timeout)


def list_pe_urls(base: str, timeout: float = 2.0, max_dirs: int = 20, max_depth: int = 2) -> list[str]:
    """PE-looking links reachable from `base` (same server only), following sub-directory links."""
    root = urllib.parse.urlsplit(base)
    out: list[str] = []
    todo, seen = [(base, 0)], {base}
    while todo and len(seen) <= max_dirs:
        page, depth = todo.pop(0)
        try:
            with _get(page, timeout) as r:
                if "html" not in (r.headers.get("Content-Type") or ""):
                    continue
                html = r.read(1_000_000).decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, ValueError):
            continue
        p = _Hrefs()
        p.feed(html)
        for h in p.hrefs:
            u = urllib.parse.urlsplit(urllib.parse.urljoin(page, h))
            if u.netloc != root.netloc or not u.path.startswith(root.path):
                continue
            url = urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, "", ""))
            if u.path.endswith("/"):
                if depth < max_depth and url not in seen:
                    seen.add(url)
                    todo.append((url, depth + 1))
            elif u.path.lower().endswith(PE_EXT) and url not in out:
                out.append(url)
    return out


def stamp(url: str, timeout: float = 2.0) -> tuple[str | None, str | None] | None:
    """(Content-Length, Last-Modified) from a HEAD request; None when the file cannot be reached."""
    try:
        with _get(url, timeout, "HEAD") as r:
            return r.headers.get("Content-Length"), r.headers.get("Last-Modified")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def fetch(url: str, cache: Path, max_bytes: int, timeout: float = 15.0) -> tuple[Path, str] | None:
    """Download `url` into cache/<sha256>/<name>. None if unreachable, oversized or not a PE (no MZ header)."""
    name = re.sub(r"[^\w.\- ]", "_", os.path.basename(urllib.parse.unquote(urllib.parse.urlsplit(url).path)))[:100] or "download.bin"
    cache.mkdir(parents=True, exist_ok=True)
    tmp = cache / f".part_{os.getpid()}_{abs(hash(url))}"
    h, n, head = hashlib.sha256(), 0, b""
    try:
        with _get(url, timeout) as r, open(tmp, "wb") as fh:
            if int(r.headers.get("Content-Length") or 0) > max_bytes:
                return None
            while chunk := r.read(1 << 16):
                n += len(chunk)
                if n > max_bytes:
                    return None
                head = head or chunk[:2]
                h.update(chunk)
                fh.write(chunk)
        if head != b"MZ":
            return None
        dest = cache / h.hexdigest() / name
        dest.parent.mkdir(exist_ok=True)
        os.replace(tmp, dest)
        return dest, h.hexdigest()
    except (urllib.error.URLError, OSError, ValueError):
        return None
    finally:
        tmp.unlink(missing_ok=True)
