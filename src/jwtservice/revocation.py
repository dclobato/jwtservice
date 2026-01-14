"""Abstracoes e implementacoes de revogacao."""

import sqlite3
import time
from typing import Any, Dict, Optional, Protocol


class RevocationStore(Protocol):
    """Interface para backends de revogacao."""

    def is_revoked(self, jti: str) -> bool:
        """Retorna True se o jti estiver revogado e nao expirado."""

    def revoke(self, jti: str, ttl_seconds: int, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Registra revogacao com TTL. Retorna True se inseriu agora."""


class InMemoryRevocationStore:
    """Revogacao em memoria com limpeza sob demanda."""

    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}

    def _purge_if_expired(self, jti: str, now: int) -> None:
        entry = self._store.get(jti)
        if entry and entry["expires_at"] <= now:
            del self._store[jti]

    def is_revoked(self, jti: str) -> bool:
        now = int(time.time())
        self._purge_if_expired(jti, now)
        return jti in self._store

    def revoke(self, jti: str, ttl_seconds: int, metadata: Optional[Dict[str, Any]] = None) -> bool:
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
    """Revogacao em SQLite com limpeza periodica."""

    def __init__(self, db_path: str, cleanup_interval_seconds: int = 300) -> None:
        if not isinstance(db_path, str) or not db_path.strip():
            raise ValueError("db_path deve ser uma string valida")
        if cleanup_interval_seconds <= 0:
            raise ValueError("cleanup_interval_seconds deve ser positivo")

        self._db_path = db_path
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
        self._conn.commit()

    def close(self) -> None:
        """Fecha a conexao com o SQLite."""
        self._conn.close()

    def _maybe_cleanup(self, now: int) -> None:
        if now - self._last_cleanup < self._cleanup_interval_seconds:
            return
        self._conn.execute("DELETE FROM revoked_tokens WHERE expires_at <= ?", (now,))
        self._conn.commit()
        self._last_cleanup = now

    def is_revoked(self, jti: str) -> bool:
        now = int(time.time())
        self._maybe_cleanup(now)
        cursor = self._conn.execute(
            "SELECT 1 FROM revoked_tokens WHERE jti = ? AND expires_at > ? LIMIT 1",
            (jti, now),
        )
        return cursor.fetchone() is not None

    def revoke(self, jti: str, ttl_seconds: int, metadata: Optional[Dict[str, Any]] = None) -> bool:
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
