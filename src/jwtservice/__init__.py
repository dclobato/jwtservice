"""Core package for JWT token generation and validation."""

from jwtservice.core import (
    JWTAction,
    JWTService,
    JWTServiceError,
    TokenConfig,
    TokenCreationError,
    TokenValidationError,
    TokenVerificationResult,
    load_token_config_from_dict,
)
from jwtservice.revocation import InMemoryRevocationStore, RevocationStore, SQLiteRevocationStore

__all__ = [
    "__version__",
    "JWTService",
    "JWTAction",
    "JWTServiceError",
    "TokenConfig",
    "TokenCreationError",
    "TokenValidationError",
    "TokenVerificationResult",
    "load_token_config_from_dict",
    "RevocationStore",
    "InMemoryRevocationStore",
    "SQLiteRevocationStore",
]

__version__ = "0.1.0"
