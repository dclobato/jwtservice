import logging

from jwtservice import JWTAction, JWTService, load_token_config_from_dict


def main() -> None:
    config = load_token_config_from_dict(
        {
            "SECRET_KEY": "my-super-secret-key",
            "JWTSERVICE_ALGORITHM": "HS256",
            "JWTSERVICE_ISSUER": "my-app",
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


if __name__ == "__main__":
    main()
