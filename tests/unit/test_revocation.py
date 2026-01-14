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
