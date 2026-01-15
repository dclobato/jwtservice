"""Serviço de geração e validação de tokens JWT.

Este módulo fornece funcionalidades para criação e verificação de tokens JWT
usados para validação de email, reset de senha e autenticação temporária.

Classes principais:
    - JWTService: Serviço para criação e validação de tokens JWT
    - JWT_action: Enum com tipos de ações de tokens
    - TokenVerificationResult: Dataclass com resultado de verificação de token
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
    """Enumeração que define as ações possíveis para tokens JWT."""

    NO_ACTION = 0
    VALIDAR_EMAIL = 1
    RESET_PASSWORD = 2
    PENDING_2FA = 3
    ACTIVATING_2FA = 4
    PENDING_PASSWORD_CHANGE = 5


class JWTServiceError(Exception):
    """Erro base para o JWTService."""


class TokenCreationError(JWTServiceError):
    """Lançado quando um token JWT não pode ser criado."""


class TokenValidationError(JWTServiceError):
    """Lançado quando um token JWT não pode ser validado."""


@dataclass
class TokenVerificationResult:
    """Resultado da verificação de um token JWT."""

    valid: bool
    status: str
    sub: Optional[str] = None
    action: Optional[Enum] = None
    age: Optional[int] = None
    aud: Optional[str] = None
    extra_data: Optional[Dict[Any, Any]] = None
    reason: Optional[str] = None


class SlidingWindowRateLimiter:
    """Rate limiter com janela deslizante para operações por minuto."""

    def __init__(self, limit_per_minute: int, time_fn: Callable[[], float] = time.monotonic):
        if not isinstance(limit_per_minute, int) or limit_per_minute <= 0:
            raise ValueError("limit_per_minute deve ser um inteiro positivo")
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
    """Serviço para criação e validação de tokens JWT."""

    def __init__(
        self,
        config: "TokenConfig",
        logger: logging.Logger,
        action_enum: Type[Enum] = JWTAction,
        revocation_store: Optional[RevocationStore] = None,
        revocation_ttl_max: Optional[int] = None,
    ) -> None:
        """Inicializa o serviço de tokens.

        Args:
            config (TokenConfig): Configurações validadas.
            logger: Logger do serviço.
            action_enum (Type[Enum]): Enum para ações do token.
            revocation_store: Backend opcional para revogação de tokens.
            revocation_ttl_max: Limite máximo de TTL em segundos para revogações.
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
                raise ValueError("revocation_ttl_max deve ser um inteiro positivo")

        if self._config.rate_limit_create_per_minute == 0:
            self._logger.warning("JWTSERVICE_RATELIMIT_CREATE=0 (sem limitacao de criacao)")
        else:
            self._rate_limiter_create = SlidingWindowRateLimiter(
                self._config.rate_limit_create_per_minute
            )

        if self._config.rate_limit_validate_per_minute == 0:
            self._logger.warning("JWTSERVICE_RATELIMIT_VALIDATE=0 (sem limitacao de validacao)")
        else:
            self._rate_limiter_validate = SlidingWindowRateLimiter(
                self._config.rate_limit_validate_per_minute
            )

        logger.debug("JWTService inicializado com algoritmo: %s", config.algorithm)

    def _get_now(self) -> int:
        return int(time.time())

    def _apply_ttl_cap(self, ttl_seconds: int) -> int:
        if self._revocation_ttl_max is None:
            return ttl_seconds
        return min(ttl_seconds, self._revocation_ttl_max)

    def _ensure_jsonable(self, data: Any) -> Any:
        """Valida que os dados podem ser serializados em JSON sem transformá-los.

        Args:
            data (Any): Dados a serem validados.

        Returns:
            Any: Os mesmos dados se forem serializáveis.

        Raises:
            TokenCreationError: Se os dados não forem serializáveis em JSON.
        """
        # Valida sem transformar, só garante serialização.
        try:
            json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise TokenCreationError("extra_data nao e serializavel em JSON") from exc
        return data

    def _enforce_create_rate_limit(self) -> None:
        if self._rate_limiter_create is None:
            return
        if self._rate_limiter_create.allow():
            return
        raise TokenCreationError("Rate limit excedido para criacao de token")

    def _enforce_validate_rate_limit(self) -> None:
        if self._rate_limiter_validate is None:
            return
        if self._rate_limiter_validate.allow():
            return
        raise TokenValidationError("Rate limit excedido para validacao de token")

    def criar(
        self,
        action: Optional[Enum] = None,
        sub: Any = None,
        expires_in: int = 600,
        audience: Optional[str] = None,
        jti: Optional[str] = None,
        extra_data: Optional[Dict[Any, Any]] = None,
    ) -> str:
        """Cria um token JWT com as claims fornecidas.

        Args:
            action (Optional[Enum]): Ação do token (usa NO_ACTION se não fornecido).
            sub (Any): Subject identifier (identificador do usuário/entidade).
            expires_in (int): Tempo de expiração em segundos (padrão: 600).
            audience (Optional[str]): Audience do token (string).
            jti (Optional[str]): JWT ID opcional. Se não fornecido, será gerado automaticamente.
            extra_data (Optional[Dict[Any, Any]]): Dados extras para incluir no payload.

        Returns:
            str: Token JWT codificado como string.

        Raises:
            ValueError: Se sub for None, vazio, não conversível para string, ou se expires_in não
                for int, ou se action não for Enum, ou se jti for inválido, ou se audience for
                inválido, ou se extra_data não for dict.
            TokenCreationError: Se houver falha ao codificar o token ou se extra_data não for
                serializável em JSON.
        """
        if sub is None:
            raise ValueError("sub deve ser informado")

        try:
            sub_str = str(sub)
        except Exception as e:
            raise ValueError(f"sub não pode ser convertido para string: {type(sub)}") from e

        if not sub_str.strip():
            raise ValueError("sub não pode ser vazio")

        if not isinstance(expires_in, int):
            raise ValueError("expires_in deve ser int")

        agora = self._get_now()
        if action is None:
            action = getattr(self._action_enum, JWTAction.NO_ACTION.name)

        if not isinstance(action, Enum):
            raise ValueError("action deve ser Enum")

        if jti is not None:
            if not isinstance(jti, str) or not jti.strip():
                raise ValueError("jti deve ser uma string nao vazia")
            jti_value = jti
        else:
            jti_value = str(uuid.uuid4())
            self._logger.debug("jti gerado automaticamente: %s", jti_value)

        payload: Dict[str, Any] = {
            "sub": sub_str,
            "iat": agora,
            "nbf": agora,
            "iss": self._config.issuer,
            "action": action.name,
            "jti": jti_value,
        }

        if expires_in > 0:
            payload["exp"] = agora + expires_in

        if audience:
            if not isinstance(audience, str) or not audience.strip():
                raise ValueError("audience deve ser uma string não vazia")
            payload["aud"] = audience
        elif self._config.audience:
            payload["aud"] = self._config.audience

        if extra_data is not None:
            if not isinstance(extra_data, dict):
                raise ValueError("extra_data deve ser dict")
            try:
                payload["extra_data"] = self._ensure_jsonable(extra_data)
            except TokenCreationError:
                self._logger.exception(
                    "Falha ao validar extra_data. action=%s sub=%s", action.name, sub_str
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
                "Falha ao gerar JWT (encode). action=%s sub=%s", action.name, sub_str
            )
            raise TokenCreationError("Falha ao gerar token") from e
        except Exception as e:
            # Última barreira. Evita 500 “misterioso” sem log.
            self._logger.exception(
                "Falha inesperada ao gerar JWT. action=%s sub=%s", action.name, sub_str
            )
            raise TokenCreationError("Falha inesperada ao gerar token") from e

        if isinstance(token, bytes):
            token = token.decode("utf-8")

        return token

    def validar(
        self, token: str, audience: Optional[Union[str, List[str]]] = None
    ) -> TokenVerificationResult:
        """Valida um token JWT e retorna um resultado estruturado.

        Args:
            token (str): Token JWT a ser validado.
            audience (Optional[Union[str, List[str]]]): Audience opcional para validar. Pode ser
                uma string ou lista de strings. Se uma lista for fornecida, o token é válido se
                seu audience corresponder a QUALQUER um dos valores na lista.

        Returns:
            TokenVerificationResult: Resultado estruturado da validação contendo status, sub,
                action, age, aud, extra_data e reason.

        Raises:
            TokenValidationError: Se houver falha inesperada ao decodificar o token.
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
            self._logger.info("JWT expirado")
            return TokenVerificationResult(valid=False, status="expired", reason="expired")
        except jwt.InvalidSignatureError:
            self._logger.warning("Assinatura inválida no JWT")
            return TokenVerificationResult(valid=False, status="invalid", reason="bad_signature")
        except jwt.ImmatureSignatureError:
            self._logger.warning("JWT ainda não válido (nbf no futuro)")
            return TokenVerificationResult(valid=False, status="invalid", reason="immature")
        except jwt.InvalidIssuerError:
            self._logger.warning("Issuer inválido no JWT")
            return TokenVerificationResult(valid=False, status="invalid", reason="invalid_issuer")
        except jwt.InvalidAudienceError:
            self._logger.warning("Audience inválido no JWT")
            return TokenVerificationResult(valid=False, status="invalid", reason="invalid_audience")
        except jwt.InvalidTokenError:
            self._logger.warning("JWT inválido")
            return TokenVerificationResult(valid=False, status="invalid", reason="invalid")
        except Exception as e:
            self._logger.exception("Falha inesperada ao decodificar JWT")
            raise TokenValidationError("Falha inesperada ao validar token") from e

        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub:
            return TokenVerificationResult(valid=False, status="invalid", reason="missing_sub")

        action_raw = payload.get("action", "NO_ACTION")
        if not isinstance(action_raw, str):
            return TokenVerificationResult(valid=False, status="invalid", reason="invalid_action")

        try:
            acao = self._action_enum[action_raw]
        except KeyError:
            return TokenVerificationResult(valid=False, status="invalid", reason="invalid_action")

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
                return TokenVerificationResult(valid=False, status="revoked", reason="revoked")

        aud = payload.get("aud")
        return TokenVerificationResult(
            valid=True,
            status="valid",
            sub=sub,
            action=acao,
            age=age,
            aud=aud if aud else None,
            extra_data=extra_data,
        )

    def revogar(
        self,
        token: str,
        reason: Optional[str] = None,
    ) -> bool:
        """Revoga um token JWT armazenando seu jti com TTL.

        Args:
            token (str): Token JWT a ser revogado.
            reason (Optional[str]): Motivo opcional para a revogação.

        Returns:
            bool: True se o token foi revogado com sucesso, False se não há revocation_store
                configurado, token inválido ou expirado.

        Raises:
            TokenValidationError: Se houver falha inesperada ao decodificar o token.
        """
        if self._revocation_store is None:
            self._logger.warning("Revogacao solicitada sem revocation_store configurado")
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
            self._logger.info("JWT expirado (revogacao ignorada)")
            return False
        except jwt.InvalidTokenError:
            self._logger.warning("JWT invalido (revogacao ignorada)")
            return False
        except Exception as e:
            self._logger.exception("Falha inesperada ao decodificar JWT para revogacao")
            raise TokenValidationError("Falha inesperada ao validar token") from e

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

    def revogar_jti(self, jti: str, exp: int, reason: Optional[str] = None) -> bool:
        """Revoga um jti conhecido usando o exp fornecido.

        Args:
            jti (str): Identificador único do token (JWT ID).
            exp (int): Timestamp de expiração do token.
            reason (Optional[str]): Motivo opcional para a revogação.

        Returns:
            bool: True se o jti foi revogado com sucesso, False se não há revocation_store
                configurado, jti inválido, ou exp já expirado.
        """
        if self._revocation_store is None:
            self._logger.warning("Revogacao solicitada sem revocation_store configurado")
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


@dataclass(frozen=True)
class TokenConfig:
    """Configuracao do JWTService."""

    secret_key: str
    algorithm: str
    audience: Optional[str]
    issuer: str
    leeway: int
    rate_limit_create_per_minute: int = 6000
    rate_limit_validate_per_minute: int = 6000

    def __post_init__(self) -> None:
        if not isinstance(self.secret_key, str) or not self.secret_key.strip():
            raise ValueError("SECRET_KEY deve ser uma string valida")

        if not isinstance(self.algorithm, str) or not self.algorithm.strip():
            raise ValueError("JWTSERVICE_ALGORITHM deve ser uma string valida")

        if self.audience is not None:
            if not isinstance(self.audience, str) or not self.audience.strip():
                raise ValueError("JWTSERVICE_AUDIENCE deve ser uma string não vazia")

        if not isinstance(self.issuer, str) or not self.issuer.strip():
            raise ValueError("JWTSERVICE_ISSUER deve ser uma string valida")

        if not isinstance(self.leeway, int) or self.leeway < 0:
            raise ValueError("JWTSERVICE_LEEWAY deve ser um inteiro nao negativo")

        if (
            not isinstance(self.rate_limit_create_per_minute, int)
            or self.rate_limit_create_per_minute < 0
        ):
            raise ValueError("JWTSERVICE_RATELIMIT_CREATE deve ser um inteiro nao negativo")

        if (
            not isinstance(self.rate_limit_validate_per_minute, int)
            or self.rate_limit_validate_per_minute < 0
        ):
            raise ValueError("JWTSERVICE_RATELIMIT_VALIDATE deve ser um inteiro nao negativo")

        algoritmo = self.algorithm.strip().upper()
        object.__setattr__(self, "algorithm", algoritmo)
        if algoritmo != "HS256":
            raise ValueError(
                "JWTSERVICE_ALGORITHM não suportado. Use HS256 (sem chaves RSA configuradas)."
            )


def load_token_config_from_dict(app_config: Dict[str, Any]) -> TokenConfig:
    """Carrega configuracoes do JWTService a partir de um dict.

    Args:
        app_config: Dicionario de configuracao da aplicacao.

    Returns:
        TokenConfig: Configuracao validada do servico.
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
