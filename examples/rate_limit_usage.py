import logging

from jwtservice import (
    JWTAction,
    JWTService,
    TokenCreationError,
    TokenValidationError,
    load_token_config_from_dict,
)


def main() -> None:
    config = load_token_config_from_dict(
        {
            "SECRET_KEY": "my-super-secret-key",
            "JWTSERVICE_ALGORITHM": "HS256",
            "JWTSERVICE_ISSUER": "my-app",
            "JWTSERVICE_RATELIMIT_CREATE": 1,
            "JWTSERVICE_RATELIMIT_VALIDATE": 1,
        }
    )

    logger = logging.getLogger("jwt")
    service = JWTService(config=config, logger=logger)

    token = service.criar(
        action=JWTAction.VALIDAR_EMAIL,
        sub="user@example.com",
        expires_in=600,
        extra_data={"flow": "signup"},
    )

    print("token:", token)
    print("result:", service.validar(token))

    try:
        service.criar(sub="another@example.com")
    except TokenCreationError as exc:
        print("create blocked:", exc)

    try:
        service.validar(token)
    except TokenValidationError as exc:
        print("validate blocked:", exc)


if __name__ == "__main__":
    main()
