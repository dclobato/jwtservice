"""Core package for JWT token generation and validation."""
from jwtservice.core import (
    JWTService,
    JWT_action,
    TokenConfig,
    TokenCreationError,
    TokenVerificationResult,
    load_token_config_from_dict,
)

__all__ = [
    "__version__",
    "JWTService",
    "JWT_action",
    "TokenConfig",
    "TokenCreationError",
    "TokenVerificationResult",
    "load_token_config_from_dict",
]

__version__ = "0.1.0"
