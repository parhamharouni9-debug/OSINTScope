"""Small cross-process request ledger for public provider budgets."""

import math
import sqlite3
import time
from pathlib import Path

from .errors import FetchError


class RateLedger:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, timeout=10)
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS cooldown (
                host TEXT PRIMARY KEY, available REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mnemonic_requests (sent REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS by_time ON mnemonic_requests(sent);
        """)

    def close(self) -> None:
        self._db.close()

    def defer(self, host: str, seconds: float) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO cooldown VALUES (?, ?) ON CONFLICT(host) DO UPDATE "
                "SET available = MAX(available, excluded.available)",
                (host, time.time() + seconds),
            )

    def acquire(self, host: str) -> None:
        mnemonic = host == "api.mnemonic.no"
        interval = 6.1 if mnemonic else 1.0
        while True:
            with self._db:
                self._db.execute("BEGIN IMMEDIATE")
                now = time.time()
                row = self._db.execute(
                    "SELECT available FROM cooldown WHERE host = ?", (host,)
                ).fetchone()
                wait = max(0.0, row[0] - now) if row else 0.0
                if not wait:
                    if mnemonic:
                        self._db.execute(
                            "DELETE FROM mnemonic_requests WHERE sent <= ?", (now - 86400,)
                        )
                        used = self._db.execute(
                            "SELECT COUNT(*) FROM mnemonic_requests"
                        ).fetchone()[0]
                        if used >= 1000:
                            raise FetchError("Local 24-hour passive DNS quota reached.")
                        self._db.execute("INSERT INTO mnemonic_requests VALUES (?)", (now,))
                    self._db.execute(
                        "INSERT OR REPLACE INTO cooldown VALUES (?, ?)", (host, now + interval)
                    )
                    return
            if wait > 15:
                raise FetchError(
                    f"Provider cooldown is active. Retry in {math.ceil(wait)} seconds."
                )
            time.sleep(wait)
