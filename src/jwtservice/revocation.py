"""Revocation abstractions and implementations."""

import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional, Protocol


class RevocationStore(Protocol):
    """Interface for revocation backends."""

    def is_revoked(self, jti: str) -> bool:
        """Check whether a jti is revoked and not expired.

        Args:
            jti (str): Unique token identifier (JWT ID).

        Returns:
            bool: True if the jti is revoked and has not expired yet, otherwise False.
        """

    def revoke(self, jti: str, ttl_seconds: int, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Register the revocation of a jti with a TTL.

        Args:
            jti (str): Unique token identifier (JWT ID).
            ttl_seconds (int): Revocation time-to-live in seconds.
            metadata (Optional[Dict[str, Any]]): Optional revocation metadata.

        Returns:
            bool: True if the revocation was inserted now, False if it already existed.
        """


class InMemoryRevocationStore:
    """In-memory revocation with on-demand cleanup."""

    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}

    def _purge_if_expired(self, jti: str, now: int) -> None:
        entry = self._store.get(jti)
        if entry and entry["expires_at"] <= now:
            del self._store[jti]

    def is_revoked(self, jti: str) -> bool:
        """Check whether a jti is revoked and not expired.

        Args:
            jti (str): Unique token identifier (JWT ID).

        Returns:
            bool: True if the jti is revoked and has not expired yet, otherwise False.
        """
        now = int(time.time())
        self._purge_if_expired(jti, now)
        return jti in self._store

    def revoke(self, jti: str, ttl_seconds: int, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Register the revocation of a jti with a TTL.

        Args:
            jti (str): Unique token identifier (JWT ID).
            ttl_seconds (int): Revocation time-to-live in seconds.
            metadata (Optional[Dict[str, Any]]): Optional revocation metadata.

        Returns:
            bool: True if the revocation was inserted now, False if it already existed or TTL is invalid.
        """
        if ttl_seconds <= 0:
            return False

        now = int(time.time())
        self._purge_if_expired(jti, now)
        if jti in self._store:
            return False

        self._store[jti] = {
            "expires_at": now + ttl_seconds,
            "metadata": metadata or {},
        }
        return True


class SQLiteRevocationStore:
    """SQLite revocation store with periodic cleanup.

    WARNING: This implementation uses check_same_thread=False and does not use
    explicit locks. For highly concurrent multi-threaded environments,
    consider using a connection pool or adding extra locking.
    """

    def __init__(self, db_path: str, cleanup_interval_seconds: int = 300) -> None:
        """Initialize the SQLite revocation store.

        Args:
            db_path (str): Path to the SQLite database file. The directory will be created if it
                does not exist.
            cleanup_interval_seconds (int): Interval in seconds for automatic cleanup of expired
                records.

        Raises:
            ValueError: If db_path is empty, cleanup_interval_seconds is not positive, or if the
                directory cannot be created.
        """
        if not isinstance(db_path, str) or not db_path.strip():
            raise ValueError("db_path must be a valid string")
        if cleanup_interval_seconds <= 0:
            raise ValueError("cleanup_interval_seconds must be positive")

        # Validate and create the directory if needed.
        db_file_path = Path(db_path).resolve()
        db_dir = db_file_path.parent

        if not db_dir.exists():
            try:
                db_dir.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise ValueError(f"Could not create directory {db_dir}: {e}") from e

        if not db_dir.is_dir():
            raise ValueError(f"Path {db_dir} exists but is not a directory")

        self._db_path = str(db_file_path)
        self._cleanup_interval_seconds = cleanup_interval_seconds
        self._last_cleanup = 0
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL,
                reason TEXT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at
            ON revoked_tokens(expires_at)
            """
        )
        self._conn.commit()

    def close(self) -> None:
        """Close the SQLite connection."""
        self._conn.close()

    def __enter__(self) -> "SQLiteRevocationStore":
        """Context manager support."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Close the connection when leaving the context."""
        self.close()

    def _maybe_cleanup(self, now: int) -> None:
        if now - self._last_cleanup < self._cleanup_interval_seconds:
            return
        self._conn.execute("DELETE FROM revoked_tokens WHERE expires_at <= ?", (now,))
        self._conn.commit()
        self._last_cleanup = now

    def is_revoked(self, jti: str) -> bool:
        """Check whether a jti is revoked and not expired.

        Args:
            jti (str): Unique token identifier (JWT ID).

        Returns:
            bool: True if the jti is revoked and has not expired yet, otherwise False.
        """
        now = int(time.time())
        self._maybe_cleanup(now)
        cursor = self._conn.execute(
            "SELECT 1 FROM revoked_tokens WHERE jti = ? AND expires_at > ? LIMIT 1",
            (jti, now),
        )
        return cursor.fetchone() is not None

    def revoke(self, jti: str, ttl_seconds: int, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Register the revocation of a jti with a TTL.

        Args:
            jti (str): Unique token identifier (JWT ID).
            ttl_seconds (int): Revocation time-to-live in seconds.
            metadata (Optional[Dict[str, Any]]): Optional revocation metadata. Only 'reason' is
                stored.

        Returns:
            bool: True if the revocation was inserted now, False if it already existed or TTL is invalid.
        """
        if ttl_seconds <= 0:
            return False

        now = int(time.time())
        self._maybe_cleanup(now)
        expires_at = now + ttl_seconds
        reason = None
        if metadata and metadata.get("reason") is not None:
            reason = str(metadata["reason"])
        cursor = self._conn.execute(
            """
            INSERT OR IGNORE INTO revoked_tokens (jti, expires_at, reason, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (jti, expires_at, reason, now),
        )
        self._conn.commit()
        return cursor.rowcount == 1
