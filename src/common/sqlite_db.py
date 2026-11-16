"""Tiny thread-safe sqlite3 wrapper: a fresh connection per call (WAL mode)."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


class DB:
    def __init__(self, path: Path, schema: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(schema)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        return c

    def q(self, sql: str, args: tuple | list = ()) -> list[dict[str, Any]]:
        c = self._conn()
        try:
            return [dict(r) for r in c.execute(sql, args).fetchall()]
        finally:
            c.close()

    def one(self, sql: str, args: tuple | list = ()) -> dict[str, Any] | None:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def val(self, sql: str, args: tuple | list = ()) -> Any:
        row = self.one(sql, args)
        return next(iter(row.values())) if row else None

    def x(self, sql: str, args: tuple | list = ()) -> int:
        c = self._conn()
        try:
            with c:
                return c.execute(sql, args).rowcount
        finally:
            c.close()

    def setting(self, key: str, default: str | None = None) -> str | None:
        v = self.val("SELECT value FROM settings WHERE key=?", (key,))
        return default if v is None else v

    def set_setting(self, key: str, value: str) -> None:
        self.x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
