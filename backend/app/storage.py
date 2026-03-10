"""Simple SQLite storage for scaffold-level persistence."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class Storage:
    """Persist scan and analysis payloads in SQLite."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def initialize(self) -> None:
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    scan_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.commit()

    def save_scan(self, payload: dict[str, Any]) -> None:
        """Store a scan payload keyed by its scan id."""
        scan_id = str(payload["scan_id"])
        target = str(payload.get("target", {}).get("input_value", "unknown"))
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO scans (scan_id, target, payload) VALUES (?, ?, ?)",
                (scan_id, target, json.dumps(payload, ensure_ascii=False)),
            )
            connection.commit()

    def save_analysis(self, payload: dict[str, Any]) -> None:
        """Store an analysis payload keyed by its scan id."""
        scan_id = str(payload["scan_id"])
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO analyses (scan_id, payload) VALUES (?, ?)",
                (scan_id, json.dumps(payload, ensure_ascii=False)),
            )
            connection.commit()

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Return a saved scan payload when present."""
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                "SELECT payload FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def get_analysis(self, scan_id: str) -> dict[str, Any] | None:
        """Return a saved analysis payload when present."""
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                "SELECT payload FROM analyses WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        """List recent scans for dashboard display."""
        with sqlite3.connect(self.db_path) as connection:
            rows = connection.execute(
                "SELECT scan_id, target, created_at FROM scans ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [{"scan_id": row[0], "target": row[1], "created_at": row[2]} for row in rows]

    def get_previous_scan_for_target(self, target: str, current_scan_id: str) -> dict[str, Any] | None:
        """Return the most recent prior scan for the same target."""
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM scans
                WHERE target = ? AND scan_id != ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (target, current_scan_id),
            ).fetchone()
        return json.loads(row[0]) if row else None
