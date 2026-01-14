import pytest

from jwtservice.revocation import InMemoryRevocationStore, SQLiteRevocationStore


def test_inmemory_revoke_and_check(monkeypatch) -> None:
    store = InMemoryRevocationStore()

    assert store.is_revoked("token-1") is False
    assert store.revoke("token-1", ttl_seconds=10) is True
    assert store.is_revoked("token-1") is True
    assert store.revoke("token-1", ttl_seconds=10) is False

    assert store.revoke("token-2", ttl_seconds=10, metadata={"reason": "logout"}) is True
    assert store.is_revoked("token-2") is True


def test_inmemory_expiration(monkeypatch) -> None:
    store = InMemoryRevocationStore()
    base_time = 1_700_000_000

    monkeypatch.setattr("jwtservice.revocation.time.time", lambda: base_time)
    assert store.revoke("token-1", ttl_seconds=5) is True
    assert store.is_revoked("token-1") is True

    monkeypatch.setattr("jwtservice.revocation.time.time", lambda: base_time + 10)
    assert store.is_revoked("token-1") is False
    assert store.revoke("token-1", ttl_seconds=0) is False


def test_sqlite_revoke_and_cleanup(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "revocations.db"
    base_time = 1_700_000_000
    monkeypatch.setattr("jwtservice.revocation.time.time", lambda: base_time)

    store = SQLiteRevocationStore(str(db_path), cleanup_interval_seconds=1)
    try:
        assert store.revoke("token-1", ttl_seconds=5, metadata={"reason": "incident"}) is True
        assert store.is_revoked("token-1") is True
        assert store.revoke("token-1", ttl_seconds=5) is False

        monkeypatch.setattr("jwtservice.revocation.time.time", lambda: base_time + 10)
        assert store.is_revoked("token-1") is False
    finally:
        store.close()


def test_sqlite_invalid_config(tmp_path) -> None:
    with pytest.raises(ValueError, match="db_path"):
        SQLiteRevocationStore("")

    with pytest.raises(ValueError, match="cleanup_interval_seconds"):
        SQLiteRevocationStore(str(tmp_path / "x.db"), cleanup_interval_seconds=0)


def test_sqlite_ttl_validation(tmp_path) -> None:
    store = SQLiteRevocationStore(str(tmp_path / "revocations.db"))
    try:
        assert store.revoke("token-1", ttl_seconds=-1) is False
    finally:
        store.close()


def test_sqlite_context_manager(tmp_path) -> None:
    db_path = tmp_path / "revocations.db"
    with SQLiteRevocationStore(str(db_path)) as store:
        assert store.revoke("token-1", ttl_seconds=10) is True
        assert store.is_revoked("token-1") is True


def test_sqlite_creates_directory_if_not_exists(tmp_path) -> None:
    """Testa que o SQLiteRevocationStore cria o diretorio se nao existir."""
    nested_dir = tmp_path / "nested" / "path" / "to" / "db"
    db_path = nested_dir / "revocations.db"

    # Diretorio nao existe ainda
    assert not nested_dir.exists()

    # Criar store deve criar o diretorio
    store = SQLiteRevocationStore(str(db_path))
    try:
        assert nested_dir.exists()
        assert nested_dir.is_dir()
        assert store.revoke("token-1", ttl_seconds=10) is True
        assert store.is_revoked("token-1") is True
    finally:
        store.close()


def test_sqlite_works_with_existing_directory(tmp_path) -> None:
    """Testa que funciona quando o diretorio ja existe."""
    db_dir = tmp_path / "existing_dir"
    db_dir.mkdir()
    db_path = db_dir / "revocations.db"

    store = SQLiteRevocationStore(str(db_path))
    try:
        assert store.revoke("token-1", ttl_seconds=10) is True
        assert store.is_revoked("token-1") is True
    finally:
        store.close()


def test_sqlite_works_with_existing_database(tmp_path) -> None:
    """Testa que funciona quando o arquivo de banco ja existe."""
    db_path = tmp_path / "revocations.db"

    # Criar primeira instancia
    store1 = SQLiteRevocationStore(str(db_path))
    try:
        assert store1.revoke("token-1", ttl_seconds=10) is True
    finally:
        store1.close()

    # Arquivo deve existir agora
    assert db_path.exists()

    # Criar segunda instancia com o mesmo arquivo
    store2 = SQLiteRevocationStore(str(db_path))
    try:
        # Deve conseguir ler o token revogado anteriormente
        assert store2.is_revoked("token-1") is True
    finally:
        store2.close()


def test_sqlite_fails_if_path_is_file_not_directory(tmp_path) -> None:
    """Testa que falha se o caminho do diretorio e um arquivo."""
    # Criar um arquivo onde deveria ser um diretorio
    file_path = tmp_path / "file.txt"
    file_path.write_text("conteudo")

    db_path = file_path / "revocations.db"

    with pytest.raises(ValueError, match="nao e um diretorio"):
        SQLiteRevocationStore(str(db_path))


def test_sqlite_fails_if_file_in_middle_of_path(tmp_path) -> None:
    """Testa que falha se um arquivo esta no meio do caminho do diretorio."""
    # Criar estrutura: /dir1/dir2/rogue_file onde rogue_file e um arquivo
    dir1 = tmp_path / "dir1"
    dir2 = dir1 / "dir2"
    dir2.mkdir(parents=True)

    rogue_file = dir2 / "rogue_file"
    rogue_file.write_text("conteudo")

    # Tentar criar banco em /dir1/dir2/rogue_file/dir3/revocations.db
    db_path = rogue_file / "dir3" / "revocations.db"

    with pytest.raises(ValueError, match="Nao foi possivel criar o diretorio"):
        SQLiteRevocationStore(str(db_path))
