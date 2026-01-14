import logging

import pytest

from jwtservice import TokenConfig, load_token_config_from_dict


@pytest.fixture()
def logger() -> logging.Logger:
    logger = logging.getLogger("jwtservice-tests")
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    return logger


@pytest.fixture()
def config() -> TokenConfig:
    return load_token_config_from_dict(
        {
            "SECRET_KEY": "test-secret",
            "JWTSERVICE_ALGORITHM": "HS256",
            "JWTSERVICE_ISSUER": "issuer",
        }
    )
