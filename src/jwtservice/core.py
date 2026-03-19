"""JWT token generation and validation service.

This module provides functionality for creating and verifying JWT tokens
used for email validation, password reset, temporary authentication, and
other optional action-tagged flows.

Main classes:
    - JWTService: Service for creating and validating JWT tokens
    - JWTAction: Enum with token action types
    - TokenVerificationResult: Dataclass with the token verification result
"""

import json
import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from typing import Any, Callable, Deque, Dict, List, Optional, Type, Union

import jwt

from jwtservice.revocation import RevocationStore


class JWTAction(Enum):
    """Enumeration that defines the possible actions for JWT tokens."""

    NO_ACTION = 0
    VALIDAR_EMAIL = 1
    RESET_PASSWORD = 2
    PENDING_2FA = 3
    ACTIVATING_2FA = 4
    PENDING_PASSWORD_CHANGE = 5


class JWTServiceError(Exception):
    """Base error for JWTService."""


class TokenCreationError(JWTServiceError):
    """Raised when a JWT token cannot be created."""


class TokenValidationError(JWTServiceError):
    """Raised when a JWT token cannot be validated."""


@dataclass
class TokenVerificationResult:
    """Result of JWT token verification.

    The ``action`` field is ``None`` when the token does not include an
    ``action`` claim.
    """

    valid: bool
    status: str
    sub: Optional[str] = None
    action: Optional[Enum] = None
    age: Optional[int] = None
    aud: Optional[str] = None
    extra_data: Optional[Dict[Any, Any]] = None
    reason: Optional[str] = None
    jti: Optional[str] = None


class SlidingWindowRateLimiter:
    """Sliding-window rate limiter for per-minute operations."""

    def __init__(self, limit_per_minute: int, time_fn: Callable[[], float] = time.monotonic):
        if not isinstance(limit_per_minute, int) or limit_per_minute <= 0:
            raise ValueError("limit_per_minute must be a positive integer")
        self._limit_per_minute = limit_per_minute
        self._time_fn = time_fn
        self._lock = Lock()
        self._timestamps: Deque[float] = deque()

    def allow(self) -> bool:
        now = self._time_fn()
        window_start = now - 60.0
        with self._lock:
            while self._timestamps and self._timestamps[0] <= window_start:
                self._timestamps.popleft()
            if len(self._timestamps) >= self._limit_per_minute:
                return False
            self._timestamps.append(now)
            return True


class JWTService:
    """Service for creating and validating JWT tokens."""

    def __init__(
        self,
        config: "TokenConfig",
        logger: logging.Logger,
        action_enum: Type[Enum] = JWTAction,
        revocation_store: Optional[RevocationStore] = None,
        revocation_ttl_max: Optional[int] = None,
    ) -> None:
        """Initialize the token service.

        Args:
            config (TokenConfig): Validated configuration.
            logger: Service logger.
            action_enum (Type[Enum]): Enum for token actions.
            revocation_store: Optional backend for token revocation.
            revocation_ttl_max: Maximum TTL limit in seconds for revocations.
        """
        self._config = config
        self._logger = logger
        self._action_enum = action_enum
        self._revocation_store = revocation_store
        self._revocation_ttl_max = revocation_ttl_max
        self._rate_limiter_create: Optional[SlidingWindowRateLimiter] = None
        self._rate_limiter_validate: Optional[SlidingWindowRateLimiter] = None

        if self._revocation_ttl_max is not None:
            if not isinstance(self._revocation_ttl_max, int) or self._revocation_ttl_max <= 0:
                raise ValueError("revocation_ttl_max must be a positive integer")

        if self._config.rate_limit_create_per_minute == 0:
            self._logger.warning("JWTSERVICE_RATELIMIT_CREATE=0 (token creation unlimited)")
        else:
            self._rate_limiter_create = SlidingWindowRateLimiter(
                self._config.rate_limit_create_per_minute
            )

        if self._config.rate_limit_validate_per_minute == 0:
            self._logger.warning("JWTSERVICE_RATELIMIT_VALIDATE=0 (token validation unlimited)")
        else:
            self._rate_limiter_validate = SlidingWindowRateLimiter(
                self._config.rate_limit_validate_per_minute
            )

        logger.debug("JWTService initialized with algorithm: %s", config.algorithm)

    def _get_now(self) -> int:
        return int(time.time())

    def _apply_ttl_cap(self, ttl_seconds: int) -> int:
        if self._revocation_ttl_max is None:
            return ttl_seconds
        return min(ttl_seconds, self._revocation_ttl_max)

    def _ensure_jsonable(self, data: Any) -> Any:
        """Validate that the data can be JSON-serialized without transforming it.

        Args:
            data (Any): Data to validate.

        Returns:
            Any: The same data if it is serializable.

        Raises:
            TokenCreationError: If the data is not JSON-serializable.
        """
        # Validate without transforming, only ensure serializability.
        try:
            json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise TokenCreationError("extra_data is not JSON-serializable") from exc
        return data

    def _enforce_create_rate_limit(self) -> None:
        if self._rate_limiter_create is None:
            return
        if self._rate_limiter_create.allow():
            return
        raise TokenCreationError("Rate limit exceeded for token creation")

    def _enforce_validate_rate_limit(self) -> None:
        if self._rate_limiter_validate is None:
            return
        if self._rate_limiter_validate.allow():
            return
        raise TokenValidationError("Rate limit exceeded for token validation")

    def criar(
        self,
        action: Optional[Enum] = None,
        sub: Any = None,
        expires_in: int = 600,
        audience: Optional[str] = None,
        jti: Optional[str] = None,
        extra_data: Optional[Dict[Any, Any]] = None,
    ) -> str:
        """Create a JWT token with the provided claims.

        Args:
            action (Optional[Enum]): Optional token action. The ``action`` claim is only
                included in the token when this argument is provided.
            sub (Any): Subject identifier (user/entity identifier).
            expires_in (int): Expiration time in seconds (default: 600).
            audience (Optional[str]): Token audience (string).
            jti (Optional[str]): Optional JWT ID. If not provided, one is generated automatically.
            extra_data (Optional[Dict[Any, Any]]): Extra data to include in the payload.

        Returns:
            str: JWT token encoded as a string.

        Raises:
            ValueError: If sub is None, empty, not convertible to string, if expires_in is not
                an int, if action is provided and is not an Enum, if jti is invalid, if
                audience is invalid, or if extra_data is not a dict.
            TokenCreationError: If token encoding fails or extra_data is not JSON-serializable.
        """
        if sub is None:
            raise ValueError("sub must be provided")

        try:
            sub_str = str(sub)
        except Exception as e:
            raise ValueError(f"sub cannot be converted to string: {type(sub)}") from e

        if not sub_str.strip():
            raise ValueError("sub cannot be empty")

        if not isinstance(expires_in, int):
            raise ValueError("expires_in must be an int")

        now = self._get_now()
        if action is not None and not isinstance(action, Enum):
            raise ValueError("action must be an Enum")

        if jti is not None:
            if not isinstance(jti, str) or not jti.strip():
                raise ValueError("jti must be a non-empty string")
            jti_value = jti
        else:
            jti_value = str(uuid.uuid4())
            self._logger.debug("jti generated automatically: %s", jti_value)

        action_name = action.name if isinstance(action, Enum) else None

        payload: Dict[str, Any] = {
            "sub": sub_str,
            "iat": now,
            "nbf": now,
            "iss": self._config.issuer,
            "jti": jti_value,
        }
        if action is not None:
            payload["action"] = action.name

        if expires_in > 0:
            payload["exp"] = now + expires_in

        if audience:
            if not isinstance(audience, str) or not audience.strip():
                raise ValueError("audience must be a non-empty string")
            payload["aud"] = audience
        elif self._config.audience:
            payload["aud"] = self._config.audience

        if extra_data is not None:
            if not isinstance(extra_data, dict):
                raise ValueError("extra_data must be a dict")
            try:
                payload["extra_data"] = self._ensure_jsonable(extra_data)
            except TokenCreationError:
                self._logger.exception(
                    "Failed to validate extra_data. action=%s sub=%s",
                    action_name,
                    sub_str,
                )
                raise

        self._enforce_create_rate_limit()

        try:
            token = jwt.encode(
                payload=payload,
                key=self._config.secret_key,
                algorithm=self._config.algorithm,
            )
        except (TypeError, ValueError, jwt.InvalidKeyError) as e:
            self._logger.exception(
                "Failed to generate JWT (encode). action=%s sub=%s", action_name, sub_str
            )
            raise TokenCreationError("Failed to generate token") from e
        except Exception as e:
            # Final safeguard. Avoids a mysterious 500 without logs.
            self._logger.exception(
                "Unexpected failure while generating JWT. action=%s sub=%s", action_name, sub_str
            )
            raise TokenCreationError("Unexpected failure while generating token") from e

        if isinstance(token, bytes):
            token = token.decode("utf-8")

        return token

    def create(
        self,
        action: Optional[Enum] = None,
        sub: Any = None,
        expires_in: int = 600,
        audience: Optional[str] = None,
        jti: Optional[str] = None,
        extra_data: Optional[Dict[Any, Any]] = None,
    ) -> str:
        """English alias for `criar` with identical behavior."""
        return self.criar(
            action=action,
            sub=sub,
            expires_in=expires_in,
            audience=audience,
            jti=jti,
            extra_data=extra_data,
        )

    def validar(
        self, token: str, audience: Optional[Union[str, List[str]]] = None
    ) -> TokenVerificationResult:
        """Validate a JWT token and return a structured result.

        Args:
            token (str): JWT token to validate.
            audience (Optional[Union[str, List[str]]]): Optional audience to validate. It may be
                a string or a list of strings. If a list is provided, the token is valid if its
                audience matches ANY value in the list.

        Returns:
            TokenVerificationResult: Structured validation result containing status, sub, action,
                age, aud, jti, extra_data, and reason. ``action`` is ``None`` when the token
                does not include an ``action`` claim.

        Raises:
            TokenValidationError: If an unexpected failure occurs while decoding the token.
        """
        if not isinstance(token, str) or not token.strip():
            return TokenVerificationResult(valid=False, status="invalid", reason="missing_token")

        self._enforce_validate_rate_limit()

        try:
            payload = jwt.decode(
                token,
                key=self._config.secret_key,
                algorithms=[self._config.algorithm],
                leeway=self._config.leeway,
                audience=audience or self._config.audience,
                issuer=self._config.issuer,
                options={
                    "verify_aud": bool(audience or self._config.audience),
                },
            )
        except jwt.ExpiredSignatureError:
            self._logger.info("JWT expired")
            return TokenVerificationResult(valid=False, status="expired", reason="expired")
        except jwt.InvalidSignatureError:
            self._logger.warning("Invalid JWT signature")
            return TokenVerificationResult(valid=False, status="invalid", reason="bad_signature")
        except jwt.ImmatureSignatureError:
            self._logger.warning("JWT not valid yet (nbf in the future)")
            return TokenVerificationResult(valid=False, status="invalid", reason="immature")
        except jwt.InvalidIssuerError:
            self._logger.warning("Invalid JWT issuer")
            return TokenVerificationResult(valid=False, status="invalid", reason="invalid_issuer")
        except jwt.InvalidAudienceError:
            self._logger.warning("Invalid JWT audience")
            return TokenVerificationResult(valid=False, status="invalid", reason="invalid_audience")
        except jwt.InvalidTokenError:
            self._logger.warning("Invalid JWT")
            return TokenVerificationResult(valid=False, status="invalid", reason="invalid")
        except Exception as e:
            self._logger.exception("Unexpected failure while decoding JWT")
            raise TokenValidationError("Unexpected failure while validating token") from e

        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub:
            return TokenVerificationResult(valid=False, status="invalid", reason="missing_sub")

        action_raw = payload.get("action")
        action = None

        if action_raw is not None:
            if not isinstance(action_raw, str):
                return TokenVerificationResult(
                    valid=False, status="invalid", reason="invalid_action"
                )
            try:
                action = self._action_enum[action_raw]
            except KeyError:
                return TokenVerificationResult(
                    valid=False, status="invalid", reason="invalid_action"
                )

        age = None
        if "iat" in payload:
            try:
                age = self._get_now() - int(payload["iat"])
            except (TypeError, ValueError):
                return TokenVerificationResult(valid=False, status="invalid", reason="invalid_iat")
            if age < 0:
                return TokenVerificationResult(valid=False, status="invalid", reason="invalid_iat")

        extra_data = payload.get("extra_data")
        if extra_data is not None and not isinstance(extra_data, dict):
            return TokenVerificationResult(
                valid=False, status="invalid", reason="invalid_extra_data"
            )

        if self._revocation_store is not None:
            jti = payload.get("jti")
            if not isinstance(jti, str) or not jti.strip():
                return TokenVerificationResult(valid=False, status="invalid", reason="missing_jti")
            if self._revocation_store.is_revoked(jti):
                return TokenVerificationResult(
                    valid=False,
                    status="revoked",
                    jti=jti,
                    reason="revoked",
                )
        else:
            jti = payload.get("jti")
            if not isinstance(jti, str) or not jti.strip():
                jti = None

        aud = payload.get("aud")
        return TokenVerificationResult(
            valid=True,
            status="valid",
            sub=sub,
            action=action,
            age=age,
            aud=aud if aud else None,
            jti=jti,
            extra_data=extra_data,
        )

    def validate(
        self, token: str, audience: Optional[Union[str, List[str]]] = None
    ) -> TokenVerificationResult:
        """English alias for `validar` with identical behavior."""
        return self.validar(token=token, audience=audience)

    def revogar(
        self,
        token: str,
        reason: Optional[str] = None,
    ) -> bool:
        """Revoke a JWT token by storing its jti with a TTL.

        Args:
            token (str): JWT token to revoke.
            reason (Optional[str]): Optional reason for the revocation.

        Returns:
            bool: True if the token was revoked successfully, False if no revocation_store is
                configured, or if the token is invalid or expired.

        Raises:
            TokenValidationError: If an unexpected failure occurs while decoding the token.
        """
        if self._revocation_store is None:
            self._logger.warning("Revocation requested without a configured revocation_store")
            return False

        if not isinstance(token, str) or not token.strip():
            return False

        try:
            payload = jwt.decode(
                token,
                key=self._config.secret_key,
                algorithms=[self._config.algorithm],
                leeway=self._config.leeway,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except jwt.ExpiredSignatureError:
            self._logger.info("JWT expired (revocation ignored)")
            return False
        except jwt.InvalidTokenError:
            self._logger.warning("Invalid JWT (revocation ignored)")
            return False
        except Exception as e:
            self._logger.exception("Unexpected failure while decoding JWT for revocation")
            raise TokenValidationError("Unexpected failure while validating token") from e

        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti.strip():
            return False

        exp = payload.get("exp")
        if not isinstance(exp, int):
            return False

        ttl_seconds = exp - self._get_now() + self._config.leeway
        if ttl_seconds <= 0:
            return False

        ttl_seconds = self._apply_ttl_cap(ttl_seconds)
        metadata = {"reason": reason} if reason else None
        return self._revocation_store.revoke(jti, ttl_seconds, metadata)

    def revoke(
        self,
        token: str,
        reason: Optional[str] = None,
    ) -> bool:
        """English alias for `revogar` with identical behavior."""
        return self.revogar(token=token, reason=reason)

    def revogar_jti(self, jti: str, exp: int, reason: Optional[str] = None) -> bool:
        """Revoke a known jti using the provided exp.

        Args:
            jti (str): Unique token identifier (JWT ID).
            exp (int): Token expiration timestamp.
            reason (Optional[str]): Optional reason for the revocation.

        Returns:
            bool: True if the jti was revoked successfully, False if no revocation_store is
                configured, if jti is invalid, or if exp has already expired.
        """
        if self._revocation_store is None:
            self._logger.warning("Revocation requested without a configured revocation_store")
            return False

        if not isinstance(jti, str) or not jti.strip():
            return False
        if not isinstance(exp, int):
            return False

        ttl_seconds = exp - self._get_now() + self._config.leeway
        if ttl_seconds <= 0:
            return False

        ttl_seconds = self._apply_ttl_cap(ttl_seconds)
        metadata = {"reason": reason} if reason else None
        return self._revocation_store.revoke(jti, ttl_seconds, metadata)

    def revoke_jti(self, jti: str, exp: int, reason: Optional[str] = None) -> bool:
        """English alias for `revogar_jti` with identical behavior."""
        return self.revogar_jti(jti=jti, exp=exp, reason=reason)


@dataclass(frozen=True)
class TokenConfig:
    """JWTService configuration."""

    secret_key: str
    algorithm: str
    audience: Optional[str]
    issuer: str
    leeway: int
    rate_limit_create_per_minute: int = 6000
    rate_limit_validate_per_minute: int = 6000

    def __post_init__(self) -> None:
        if not isinstance(self.secret_key, str) or not self.secret_key.strip():
            raise ValueError("SECRET_KEY must be a valid string")

        if not isinstance(self.algorithm, str) or not self.algorithm.strip():
            raise ValueError("JWTSERVICE_ALGORITHM must be a valid string")

        if self.audience is not None:
            if not isinstance(self.audience, str) or not self.audience.strip():
                raise ValueError("JWTSERVICE_AUDIENCE must be a non-empty string")

        if not isinstance(self.issuer, str) or not self.issuer.strip():
            raise ValueError("JWTSERVICE_ISSUER must be a valid string")

        if not isinstance(self.leeway, int) or self.leeway < 0:
            raise ValueError("JWTSERVICE_LEEWAY must be a non-negative integer")

        if (
            not isinstance(self.rate_limit_create_per_minute, int)
            or self.rate_limit_create_per_minute < 0
        ):
            raise ValueError("JWTSERVICE_RATELIMIT_CREATE must be a non-negative integer")

        if (
            not isinstance(self.rate_limit_validate_per_minute, int)
            or self.rate_limit_validate_per_minute < 0
        ):
            raise ValueError("JWTSERVICE_RATELIMIT_VALIDATE must be a non-negative integer")

        normalized_algorithm = self.algorithm.strip().upper()
        object.__setattr__(self, "algorithm", normalized_algorithm)
        if normalized_algorithm != "HS256":
            raise ValueError(
                "JWTSERVICE_ALGORITHM is not supported. Use HS256 (no RSA keys configured)."
            )


def load_token_config_from_dict(app_config: Dict[str, Any]) -> TokenConfig:
    """Load JWTService configuration from a dict.

    Args:
        app_config: Application configuration dictionary.

    Returns:
        TokenConfig: Validated service configuration.
    """
    app_config.setdefault("JWTSERVICE_ALGORITHM", "HS256")
    app_config.setdefault("JWTSERVICE_ISSUER", "JWTService")
    app_config.setdefault("JWTSERVICE_LEEWAY", 0)
    app_config.setdefault("JWTSERVICE_RATELIMIT", 6000)
    app_config.setdefault("JWTSERVICE_RATELIMIT_CREATE", app_config.get("JWTSERVICE_RATELIMIT"))
    app_config.setdefault("JWTSERVICE_RATELIMIT_VALIDATE", app_config.get("JWTSERVICE_RATELIMIT"))

    secret_key = app_config.get("SECRET_KEY")
    if secret_key is None:
        raise ValueError("SECRET_KEY must be provided in app_config")

    return TokenConfig(
        secret_key=str(secret_key),
        algorithm=str(app_config.get("JWTSERVICE_ALGORITHM")),
        audience=(
            str(app_config.get("JWTSERVICE_AUDIENCE"))
            if app_config.get("JWTSERVICE_AUDIENCE")
            else None
        ),
        issuer=str(app_config.get("JWTSERVICE_ISSUER")),
        leeway=int(app_config.get("JWTSERVICE_LEEWAY") or 0),
        rate_limit_create_per_minute=int(app_config.get("JWTSERVICE_RATELIMIT_CREATE") or 0),
        rate_limit_validate_per_minute=int(app_config.get("JWTSERVICE_RATELIMIT_VALIDATE") or 0),
    )
