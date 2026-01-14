import logging

from jwtservice import (
    InMemoryRevocationStore,
    JWTService,
    SQLiteRevocationStore,
    load_token_config_from_dict,
)


def build_service(store):
    config = load_token_config_from_dict(
        {
            "SECRET_KEY": "my-super-secret-key",
            "JWTSERVICE_ALGORITHM": "HS256",
            "JWTSERVICE_ISSUER": "my-app",
        }
    )
    logger = logging.getLogger("jwt")
    return JWTService(config=config, logger=logger, revocation_store=store)


def run_in_memory_example() -> None:
    print("=== In-memory revocation store ===")
    store = InMemoryRevocationStore()
    service = build_service(store)

    token = service.criar(sub="user@example.com")
    print("Before revoke:", service.validar(token).status)

    service.revogar(token, reason="logout")
    print("After revoke:", service.validar(token).status)


def run_sqlite_example() -> None:
    print("=== SQLite revocation store ===")
    store = SQLiteRevocationStore("revocations.db")
    service = build_service(store)

    token = service.criar(sub="user@example.com")
    print("Before revoke:", service.validar(token).status)

    service.revogar(token, reason="incident")
    print("After revoke:", service.validar(token).status)


if __name__ == "__main__":
    run_in_memory_example()
    run_sqlite_example()
