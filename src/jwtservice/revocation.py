"""Abstracoes e implementacoes de revogacao."""

import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional, Protocol


class RevocationStore(Protocol):
    """Interface para backends de revogacao."""

    def is_revoked(self, jti: str) -> bool:
        """Verifica se um jti esta revogado e nao expirado.

        Args:
            jti (str): Identificador unico do token (JWT ID).

        Returns:
            bool: True se o jti estiver revogado e ainda nao expirou, False caso contrario.
        """

    def revoke(self, jti: str, ttl_seconds: int, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Registra a revogacao de um jti com TTL.

        Args:
            jti (str): Identificador unico do token (JWT ID).
            ttl_seconds (int): Tempo de vida da revogacao em segundos.
            metadata (Optional[Dict[str, Any]]): Metadados opcionais da revogacao.

        Returns:
            bool: True se a revogacao foi inserida agora, False se ja existia.
        """


class InMemoryRevocationStore:
    """Revogacao em memoria com limpeza sob demanda."""

    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}

    def _purge_if_expired(self, jti: str, now: int) -> None:
        entry = self._store.get(jti)
        if entry and entry["expires_at"] <= now:
            del self._store[jti]

    def is_revoked(self, jti: str) -> bool:
        """Verifica se um jti esta revogado e nao expirado.

        Args:
            jti (str): Identificador unico do token (JWT ID).

        Returns:
            bool: True se o jti estiver revogado e ainda nao expirou, False caso contrario.
        """
        now = int(time.time())
        self._purge_if_expired(jti, now)
        return jti in self._store

    def revoke(self, jti: str, ttl_seconds: int, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Registra a revogacao de um jti com TTL.

        Args:
            jti (str): Identificador unico do token (JWT ID).
            ttl_seconds (int): Tempo de vida da revogacao em segundos.
            metadata (Optional[Dict[str, Any]]): Metadados opcionais da revogacao.

        Returns:
            bool: True se a revogacao foi inserida agora, False se ja existia ou ttl invalido.
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
    """Revogacao em SQLite com limpeza periodica.

    AVISO: Esta implementacao usa check_same_thread=False e nao possui
    locks explícitos. Para ambientes multi-threaded com alta concorrencia,
    considere usar um pool de conexoes ou implementar locking adicional.
    """

    def __init__(self, db_path: str, cleanup_interval_seconds: int = 300) -> None:
        """Inicializa o store de revogacao com SQLite.

        Args:
            db_path (str): Caminho do arquivo do banco de dados SQLite. O diretorio sera criado
                se nao existir.
            cleanup_interval_seconds (int): Intervalo em segundos para limpeza automatica de
                registros expirados.

        Raises:
            ValueError: Se db_path for vazio, cleanup_interval_seconds nao for positivo, ou se
                nao for possivel criar o diretorio.
        """
        if not isinstance(db_path, str) or not db_path.strip():
            raise ValueError("db_path deve ser uma string valida")
        if cleanup_interval_seconds <= 0:
            raise ValueError("cleanup_interval_seconds deve ser positivo")

        # Validar e criar diretorio se necessario
        db_file_path = Path(db_path).resolve()
        db_dir = db_file_path.parent

        if not db_dir.exists():
            try:
                db_dir.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise ValueError(f"Nao foi possivel criar o diretorio {db_dir}: {e}") from e

        if not db_dir.is_dir():
            raise ValueError(f"O caminho {db_dir} existe mas nao e um diretorio")

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
        """Fecha a conexao com o SQLite."""
        self._conn.close()

    def __enter__(self) -> "SQLiteRevocationStore":
        """Suporte para context manager."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Fecha a conexao ao sair do contexto."""
        self.close()

    def _maybe_cleanup(self, now: int) -> None:
        if now - self._last_cleanup < self._cleanup_interval_seconds:
            return
        self._conn.execute("DELETE FROM revoked_tokens WHERE expires_at <= ?", (now,))
        self._conn.commit()
        self._last_cleanup = now

    def is_revoked(self, jti: str) -> bool:
        """Verifica se um jti esta revogado e nao expirado.

        Args:
            jti (str): Identificador unico do token (JWT ID).

        Returns:
            bool: True se o jti estiver revogado e ainda nao expirou, False caso contrario.
        """
        now = int(time.time())
        self._maybe_cleanup(now)
        cursor = self._conn.execute(
            "SELECT 1 FROM revoked_tokens WHERE jti = ? AND expires_at > ? LIMIT 1",
            (jti, now),
        )
        return cursor.fetchone() is not None

    def revoke(self, jti: str, ttl_seconds: int, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Registra a revogacao de um jti com TTL.

        Args:
            jti (str): Identificador unico do token (JWT ID).
            ttl_seconds (int): Tempo de vida da revogacao em segundos.
            metadata (Optional[Dict[str, Any]]): Metadados opcionais da revogacao. Apenas 'reason'
                e armazenado.

        Returns:
            bool: True se a revogacao foi inserida agora, False se ja existia ou ttl invalido.
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
