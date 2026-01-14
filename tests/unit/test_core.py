import time

import jwt
import pytest

from jwtservice import (
    JWTAction,
    JWTService,
    TokenConfig,
    TokenCreationError,
    TokenValidationError,
    load_token_config_from_dict,
)


def test_create_and_validate_token(config, logger) -> None:
    service = JWTService(config=config, logger=logger)
    token = service.criar(
        action=JWTAction.VALIDAR_EMAIL,
        sub="user@example.com",
        expires_in=300,
        extra_data={"flow": "signup"},
    )

    result = service.validar(token)

    assert result.valid is True
    assert result.sub == "user@example.com"
    assert result.action == JWTAction.VALIDAR_EMAIL
    assert result.extra_data == {"flow": "signup"}
    assert result.age is not None


def test_create_without_action_defaults_to_no_action(config, logger) -> None:
    service = JWTService(config=config, logger=logger)
    token = service.criar(sub="user@example.com")

    result = service.validar(token)

    assert result.valid is True
    assert result.action == JWTAction.NO_ACTION


def test_invalid_signature_returns_reason(logger) -> None:
    service_a = JWTService(
        config=TokenConfig("secret-a", "HS256", None, "issuer", 0), logger=logger
    )
    service_b = JWTService(
        config=TokenConfig("secret-b", "HS256", None, "issuer", 0), logger=logger
    )

    token = service_a.criar(sub="user@example.com")
    result = service_b.validar(token)

    assert result.valid is False
    assert result.reason == "bad_signature"


def test_expired_token_returns_reason(config, logger) -> None:
    now = int(time.time())
    payload = {
        "sub": "user@example.com",
        "iat": now - 20,
        "nbf": now - 20,
        "exp": now - 10,
        "action": "NO_ACTION",
    }
    token = jwt.encode(payload, key=config.secret_key, algorithm=config.algorithm)

    service = JWTService(config=config, logger=logger)
    result = service.validar(token)

    assert result.valid is False
    assert result.reason == "expired"


def test_invalid_action_returns_reason(config, logger) -> None:
    now = int(time.time())
    payload = {
        "sub": "user@example.com",
        "iat": now,
        "nbf": now,
        "iss": "issuer",
        "action": "UNKNOWN_ACTION",
    }
    token = jwt.encode(payload, key=config.secret_key, algorithm=config.algorithm)

    service = JWTService(config=config, logger=logger)
    result = service.validar(token)

    assert result.valid is False
    assert result.reason == "invalid_action"


def test_create_requires_sub(config, logger) -> None:
    service = JWTService(config=config, logger=logger)

    with pytest.raises(ValueError, match="sub deve ser informado"):
        service.criar()


def test_create_rejects_empty_sub(config, logger) -> None:
    service = JWTService(config=config, logger=logger)

    with pytest.raises(ValueError, match="sub .* vazio"):
        service.criar(sub=" ")


def test_create_rejects_unstringable_sub(config, logger) -> None:
    class BadStr:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    service = JWTService(config=config, logger=logger)

    with pytest.raises(ValueError, match="sub .* convertido"):
        service.criar(sub=BadStr())


def test_create_rejects_invalid_expires_in(config, logger) -> None:
    service = JWTService(config=config, logger=logger)

    with pytest.raises(ValueError, match="expires_in deve ser int"):
        service.criar(sub="user@example.com", expires_in="10")  # type: ignore[arg-type]


def test_create_rejects_invalid_action_type(config, logger) -> None:
    service = JWTService(config=config, logger=logger)

    with pytest.raises(ValueError, match="action deve ser Enum"):
        service.criar(sub="user@example.com", action="x")  # type: ignore[arg-type]


def test_create_rejects_invalid_extra_data_type(config, logger) -> None:
    service = JWTService(config=config, logger=logger)

    with pytest.raises(ValueError, match="extra_data deve ser dict"):
        service.criar(sub="user@example.com", extra_data=["x"])  # type: ignore[arg-type]


def test_create_rejects_non_jsonable_extra_data(config, logger) -> None:
    service = JWTService(config=config, logger=logger)

    with pytest.raises(TokenCreationError, match="extra_data nao e serializavel"):
        service.criar(sub="user@example.com", extra_data={"bad": {1, 2}})


def test_create_handles_encode_errors(config, logger, monkeypatch) -> None:
    service = JWTService(config=config, logger=logger)

    def raise_type_error(*args, **kwargs):
        raise TypeError("encode failed")

    monkeypatch.setattr(jwt, "encode", raise_type_error)

    with pytest.raises(TokenCreationError, match="Falha ao gerar token"):
        service.criar(sub="user@example.com")


def test_create_handles_unexpected_encode_errors(config, logger, monkeypatch) -> None:
    service = JWTService(config=config, logger=logger)

    def raise_unexpected(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(jwt, "encode", raise_unexpected)

    with pytest.raises(TokenCreationError, match="Falha inesperada ao gerar token"):
        service.criar(sub="user@example.com")


def test_validate_missing_token(config, logger) -> None:
    service = JWTService(config=config, logger=logger)

    result = service.validar(" ")

    assert result.valid is False
    assert result.reason == "missing_token"


def test_validate_invalid_action_type(config, logger) -> None:
    now = int(time.time())
    payload = {
        "sub": "user@example.com",
        "iat": now,
        "nbf": now,
        "iss": "issuer",
        "action": 123,
    }
    token = jwt.encode(payload, key=config.secret_key, algorithm=config.algorithm)

    service = JWTService(config=config, logger=logger)
    result = service.validar(token)

    assert result.valid is False
    assert result.reason == "invalid_action"


def test_validate_missing_sub(config, logger) -> None:
    now = int(time.time())
    payload = {
        "iat": now,
        "nbf": now,
        "iss": "issuer",
        "action": "NO_ACTION",
    }
    token = jwt.encode(payload, key=config.secret_key, algorithm=config.algorithm)

    service = JWTService(config=config, logger=logger)
    result = service.validar(token)

    assert result.valid is False
    assert result.reason == "missing_sub"


def test_validate_invalid_iat(config, logger) -> None:
    payload = {
        "sub": "user@example.com",
        "iat": "bad",
        "nbf": int(time.time()),
        "action": "NO_ACTION",
    }
    token = jwt.encode(payload, key=config.secret_key, algorithm=config.algorithm)

    service = JWTService(config=config, logger=logger)
    result = service.validar(token)

    assert result.valid is False
    assert result.reason == "invalid"


def test_validate_invalid_extra_data(config, logger) -> None:
    now = int(time.time())
    payload = {
        "sub": "user@example.com",
        "iat": now,
        "nbf": now,
        "action": "NO_ACTION",
        "iss": "issuer",
        "extra_data": "oops",
    }
    token = jwt.encode(payload, key=config.secret_key, algorithm=config.algorithm)

    service = JWTService(config=config, logger=logger)
    result = service.validar(token)

    assert result.valid is False
    assert result.reason == "invalid_extra_data"


def test_validate_immature_signature(config, logger, monkeypatch) -> None:
    service = JWTService(config=config, logger=logger)

    def raise_immature(*args, **kwargs):
        raise jwt.ImmatureSignatureError("nbf in future")

    monkeypatch.setattr(jwt, "decode", raise_immature)

    result = service.validar("token")

    assert result.valid is False
    assert result.reason == "immature"


def test_validate_invalid_token(config, logger, monkeypatch) -> None:
    service = JWTService(config=config, logger=logger)

    def raise_invalid(*args, **kwargs):
        raise jwt.InvalidTokenError("invalid")

    monkeypatch.setattr(jwt, "decode", raise_invalid)

    result = service.validar("token")

    assert result.valid is False
    assert result.reason == "invalid"


def test_validate_internal_error(config, logger, monkeypatch) -> None:
    service = JWTService(config=config, logger=logger)

    def raise_unexpected(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(jwt, "decode", raise_unexpected)

    with pytest.raises(TokenValidationError, match="Falha inesperada ao validar token"):
        service.validar("token")


def test_load_config_defaults_algorithm() -> None:
    config = load_token_config_from_dict({"SECRET_KEY": "secret"})
    assert config.algorithm == "HS256"


def test_invalid_algorithm_raises() -> None:
    try:
        load_token_config_from_dict(
            {
                "SECRET_KEY": "secret",
                "JWTSERVICE_ALGORITHM": "RS256",
            }
        )
    except ValueError as exc:
        assert "JWTSERVICE_ALGORITHM" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_invalid_secret_key_raises() -> None:
    with pytest.raises(ValueError, match="SECRET_KEY"):
        TokenConfig("", "HS256", None, "issuer", 0)


def test_invalid_algorithm_empty_raises() -> None:
    with pytest.raises(ValueError, match="JWTSERVICE_ALGORITHM"):
        TokenConfig("secret", "", None, "issuer", 0)


def test_create_token_with_custom_audience(config, logger) -> None:
    service = JWTService(config=config, logger=logger)
    token = service.criar(
        sub="user@example.com",
        audience="custom-audience",
    )

    result = service.validar(token, audience="custom-audience")

    assert result.valid is True
    assert result.aud == "custom-audience"


def test_create_token_with_config_audience(logger) -> None:
    config = TokenConfig("secret", "HS256", "default-audience", "issuer", 0)
    service = JWTService(config=config, logger=logger)
    token = service.criar(sub="user@example.com")

    result = service.validar(token)

    assert result.valid is True
    assert result.aud == "default-audience"


def test_validate_token_with_string_audience(config, logger) -> None:
    service = JWTService(config=config, logger=logger)
    token = service.criar(sub="user@example.com", audience="api-service")

    result = service.validar(token, audience="api-service")

    assert result.valid is True


def test_validate_token_with_list_audience_match(config, logger) -> None:
    service = JWTService(config=config, logger=logger)
    token = service.criar(sub="user@example.com", audience="api-service")

    result = service.validar(token, audience=["web-app", "api-service", "mobile-app"])

    assert result.valid is True


def test_validate_token_with_list_audience_no_match(config, logger) -> None:
    service = JWTService(config=config, logger=logger)
    token = service.criar(sub="user@example.com", audience="api-service")

    result = service.validar(token, audience=["web-app", "mobile-app"])

    assert result.valid is False
    assert result.reason == "invalid_audience"


def test_validate_token_audience_mismatch(config, logger) -> None:
    service = JWTService(config=config, logger=logger)
    token = service.criar(sub="user@example.com", audience="api-service")

    result = service.validar(token, audience="wrong-audience")

    assert result.valid is False
    assert result.reason == "invalid_audience"


def test_create_rejects_empty_audience(config, logger) -> None:
    service = JWTService(config=config, logger=logger)

    with pytest.raises(ValueError, match="audience deve ser uma string não vazia"):
        service.criar(sub="user@example.com", audience=" ")


def test_create_rejects_non_string_audience(config, logger) -> None:
    service = JWTService(config=config, logger=logger)

    with pytest.raises(ValueError, match="audience deve ser uma string não vazia"):
        service.criar(sub="user@example.com", audience=123)  # type: ignore[arg-type]


def test_config_rejects_empty_audience() -> None:
    with pytest.raises(ValueError, match="JWTSERVICE_AUDIENCE"):
        TokenConfig("secret", "HS256", " ", "issuer", 0)


def test_config_rejects_non_string_audience() -> None:
    with pytest.raises(ValueError, match="JWTSERVICE_AUDIENCE"):
        TokenConfig("secret", "HS256", 123, "issuer", 0)  # type: ignore[arg-type]


def test_validate_issuer_mismatch(config, logger) -> None:
    service_a = JWTService(
        config=TokenConfig("secret", "HS256", None, "issuer-a", 0), logger=logger
    )
    service_b = JWTService(
        config=TokenConfig("secret", "HS256", None, "issuer-b", 0), logger=logger
    )

    token = service_a.criar(sub="user@example.com")
    result = service_b.validar(token)

    assert result.valid is False
    assert result.reason == "invalid_issuer"
