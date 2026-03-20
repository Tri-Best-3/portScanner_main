"""SQLite storage for scans, analyses, reports, runs, inventories, and verifications."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class Storage:
    """Persist backend payloads in SQLite."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=30)

    def initialize(self) -> None:
        with self._connect() as connection:
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
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    scan_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS inventories (
                    inventory_id TEXT PRIMARY KEY,
                    scope TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS verifications (
                    verification_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.commit()

    def save_scan(self, payload: dict[str, Any]) -> None:
        scan_id = str(payload["scan_id"])
        target = str(payload.get("target", {}).get("input_value", "unknown"))
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO scans (scan_id, target, payload) VALUES (?, ?, ?)",
                (scan_id, target, json.dumps(payload, ensure_ascii=False, default=str)),
            )
            connection.commit()

    def save_analysis(self, payload: dict[str, Any]) -> None:
        scan_id = str(payload["scan_id"])
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO analyses (scan_id, payload) VALUES (?, ?)",
                (scan_id, json.dumps(payload, ensure_ascii=False, default=str)),
            )
            connection.commit()

    def save_report(self, payload: dict[str, Any]) -> None:
        scan_id = str(payload["scan_id"])
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO reports (scan_id, payload) VALUES (?, ?)",
                (scan_id, json.dumps(payload, ensure_ascii=False, default=str)),
            )
            connection.commit()

    def save_run(self, payload: dict[str, Any]) -> None:
        run_id = str(payload["run_id"])
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO runs (run_id, payload) VALUES (?, ?)",
                (run_id, json.dumps(payload, ensure_ascii=False, default=str)),
            )
            connection.commit()

    def save_inventory(self, payload: dict[str, Any]) -> None:
        inventory_id = str(payload["inventory_id"])
        scope = str(payload["scope"])
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO inventories (inventory_id, scope, payload) VALUES (?, ?, ?)",
                (inventory_id, scope, json.dumps(payload, ensure_ascii=False, default=str)),
            )
            connection.commit()

    def save_verification(self, payload: dict[str, Any]) -> None:
        verification_id = str(payload["verification_id"])
        scan_id = str(payload["scan_id"])
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO verifications (verification_id, scan_id, payload) VALUES (?, ?, ?)",
                (verification_id, scan_id, json.dumps(payload, ensure_ascii=False, default=str)),
            )
            connection.commit()

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def get_analysis(self, scan_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM analyses WHERE scan_id = ?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def get_report(self, scan_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM reports WHERE scan_id = ?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def get_inventory(self, inventory_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM inventories WHERE inventory_id = ?",
                (inventory_id,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def list_verifications(self, scan_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM verifications
                WHERE scan_id = ?
                ORDER BY created_at DESC
                """,
                (scan_id,),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT scan_id, target, created_at FROM scans ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [{"scan_id": row[0], "target": row[1], "created_at": row[2]} for row in rows]

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT run_id, payload, created_at FROM runs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "run_id": row[0],
                "created_at": row[2],
                "status": json.loads(row[1]).get("status"),
                "item_count": len(json.loads(row[1]).get("items", [])),
            }
            for row in rows
        ]

    def list_inventories(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT inventory_id, scope, created_at FROM inventories ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [{"inventory_id": row[0], "scope": row[1], "created_at": row[2]} for row in rows]

    def get_previous_scan_for_target(self, target: str, current_scan_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
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

    def get_previous_inventory_for_scope(self, scope: str, current_inventory_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM inventories
                WHERE scope = ? AND inventory_id != ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (scope, current_inventory_id),
            ).fetchone()
        return json.loads(row[0]) if row else None
