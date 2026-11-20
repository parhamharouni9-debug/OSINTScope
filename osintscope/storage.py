"""Transactional, versioned SQLite storage for local investigation history."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from .models import Coverage, Investigation, Observation, Relationship, coverage_status

_APPLICATION_ID = 0x4F53494E  # SQLite file header identifier: OSIN
_VERSION = 1
_SCHEMA = (
    """CREATE TABLE investigation (
        id INTEGER PRIMARY KEY, domain TEXT NOT NULL,
        started_at TEXT NOT NULL, finished_at TEXT NOT NULL, status TEXT NOT NULL
    )""",
    """CREATE INDEX investigation_domain_time
       ON investigation(domain, started_at DESC, id DESC)""",
    """CREATE TABLE observation (
        investigation_id INTEGER NOT NULL REFERENCES investigation(id),
        kind TEXT NOT NULL, subject TEXT NOT NULL, value TEXT NOT NULL,
        source TEXT NOT NULL, reference TEXT NOT NULL, observed_at TEXT NOT NULL,
        details TEXT NOT NULL
    )""",
    """CREATE INDEX observation_investigation
       ON observation(investigation_id, kind, subject)""",
    """CREATE TABLE coverage (
        investigation_id INTEGER NOT NULL REFERENCES investigation(id),
        key TEXT NOT NULL, status TEXT NOT NULL, message TEXT NOT NULL,
        PRIMARY KEY(investigation_id, key),
        CHECK(status IN ('complete', 'partial', 'failed'))
    )""",
    """CREATE TABLE relationship (
        investigation_id INTEGER NOT NULL REFERENCES investigation(id),
        subject TEXT NOT NULL, predicate TEXT NOT NULL, object TEXT NOT NULL,
        basis TEXT NOT NULL, confidence TEXT NOT NULL, reason TEXT NOT NULL,
        sources TEXT NOT NULL, CHECK(basis IN ('observed', 'inferred'))
    )""",
    "CREATE INDEX relationship_investigation ON relationship(investigation_id)",
)


class Repository:
    def __init__(self, path: Path | str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, timeout=10)
        self._db.row_factory = sqlite3.Row
        try:
            self._db.execute("PRAGMA foreign_keys = ON")
            self._initialize()
        except BaseException:
            self.close()
            raise

    def _schema_identity(self) -> tuple[int, int]:
        app_id = self._db.execute("PRAGMA application_id").fetchone()[0]
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        return app_id, version

    def _initialize(self) -> None:
        if self._schema_identity() == (_APPLICATION_ID, _VERSION):
            return
        # Serialize initializers so concurrent first scans can share a new file.
        with self._db:
            self._db.execute("BEGIN IMMEDIATE")
            app_id, version = self._schema_identity()
            if (app_id, version) == (_APPLICATION_ID, _VERSION):
                return
            existing_schema = self._db.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
            if app_id or version or existing_schema:
                raise sqlite3.DatabaseError(
                    "The selected file is not a compatible OSINTScope database."
                )
            for statement in _SCHEMA:
                self._db.execute(statement)
            self._db.execute(f"PRAGMA application_id = {_APPLICATION_ID:d}")
            self._db.execute(f"PRAGMA user_version = {_VERSION:d}")

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._db.close()

    def save(self, scan: Investigation) -> int:
        """Append a complete snapshot in one transaction and return its local ID."""
        if scan.id is not None:
            raise ValueError("Only an investigation without a database ID can be saved.")
        with self._db:
            cursor = self._db.execute(
                """INSERT INTO investigation(domain, started_at, finished_at, status)
                   VALUES (?, ?, ?, ?)""",
                (
                    scan.domain,
                    scan.started_at,
                    scan.finished_at,
                    coverage_status(scan.coverage),
                ),
            )
            scan_id = cursor.lastrowid
            assert scan_id is not None
            self._db.executemany(
                "INSERT INTO coverage VALUES (?, ?, ?, ?)",
                ((scan_id, c.key, c.status, c.message) for c in scan.coverage),
            )
            self._db.executemany(
                "INSERT INTO observation VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        scan_id,
                        o.kind,
                        o.subject,
                        o.value,
                        o.source,
                        o.reference,
                        o.observed_at,
                        json.dumps(o.details, sort_keys=True),
                    )
                    for o in scan.observations
                ),
            )
            self._db.executemany(
                "INSERT INTO relationship VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        scan_id,
                        r.subject,
                        r.predicate,
                        r.object,
                        r.basis,
                        r.confidence,
                        r.reason,
                        json.dumps(r.sources),
                    )
                    for r in scan.relationships
                ),
            )
        return scan_id

    def history(self, domain: str) -> list[dict[str, Any]]:
        records = self._db.execute(
            """SELECT i.id, i.domain, i.started_at, i.finished_at, i.status,
                      (SELECT COUNT(*) FROM observation o WHERE o.investigation_id = i.id)
                      AS observations
               FROM investigation i WHERE i.domain = ?
               ORDER BY i.started_at DESC, i.id DESC""",
            (domain,),
        )
        return [dict(row) for row in records]

    def latest(self, domain: str, limit: int = 1) -> list[Investigation]:
        if limit < 0:
            raise ValueError("The investigation limit must be nonnegative.")
        rows = self._db.execute(
            """SELECT * FROM investigation WHERE domain = ?
               ORDER BY started_at DESC, id DESC LIMIT ?""",
            (domain, limit),
        )
        return [self._load(row) for row in rows]

    def get(self, scan_id: int) -> Investigation | None:
        row = self._db.execute(
            "SELECT * FROM investigation WHERE id = ?",
            (scan_id,),
        ).fetchone()
        return self._load(row) if row is not None else None

    def _load(self, row: sqlite3.Row) -> Investigation:
        params = (row["id"],)
        observations = [
            Observation(
                o["kind"],
                o["subject"],
                o["value"],
                o["source"],
                o["reference"],
                o["observed_at"],
                json.loads(o["details"]),
            )
            for o in self._db.execute(
                "SELECT * FROM observation WHERE investigation_id = ? ORDER BY rowid",
                params,
            )
        ]
        coverage = [
            Coverage(c["key"], c["status"], c["message"])
            for c in self._db.execute(
                "SELECT * FROM coverage WHERE investigation_id = ? ORDER BY rowid",
                params,
            )
        ]
        relationships = [
            Relationship(
                r["subject"],
                r["predicate"],
                r["object"],
                r["basis"],
                r["confidence"],
                r["reason"],
                json.loads(r["sources"]),
            )
            for r in self._db.execute(
                "SELECT * FROM relationship WHERE investigation_id = ? ORDER BY rowid",
                params,
            )
        ]
        return Investigation(
            row["id"],
            row["domain"],
            row["started_at"],
            row["finished_at"],
            observations,
            coverage,
            relationships,
        )
