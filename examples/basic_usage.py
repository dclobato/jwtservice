import logging

from jwtservice import JWT_action, JWTService, load_token_config_from_dict


def main() -> None:
    config = load_token_config_from_dict(
        {
            "SECRET_KEY": "minha-chave-super-secreta",
            "JWT_ALGORITHM": "HS256",
        }
    )

    logger = logging.getLogger("jwt")
    service = JWTService(config=config, logger=logger)

    token = service.criar(
        action=JWT_action.VALIDAR_EMAIL,
        sub="usuario@example.com",
        expires_in=600,
        extra_data={"flow": "cadastro"},
    )

    print("token:", token)
    print("result:", service.validar(token))


if __name__ == "__main__":
    main()
