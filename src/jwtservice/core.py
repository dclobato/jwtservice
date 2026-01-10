"""Serviço de geração e validação de tokens JWT.

Este módulo fornece funcionalidades para criação e verificação de tokens JWT
usados para validação de email, reset de senha e autenticação temporária.

Classes principais:
    - JWTService: Serviço para criação e validação de tokens JWT
    - JWT_action: Enum com tipos de ações de tokens
    - TokenVerificationResult: Dataclass com resultado de verificação de token
"""
from dataclasses import dataclass
from enum import Enum
import time
import json
import logging
from typing import Any, Dict, Optional, Type

import jwt


class JWT_action(Enum):
    """Enumeração que define as ações possíveis para tokens JWT."""

    NO_ACTION = 0
    VALIDAR_EMAIL = 1
    RESET_PASSWORD = 2
    PENDING_2FA = 3
    ACTIVATING_2FA = 4
    PENDING_PASSWORD_CHANGE = 5


class TokenCreationError(Exception):
    """Raised when a JWT token cannot be created."""


@dataclass
class TokenVerificationResult:
    """Resultado da verificação de um token JWT."""

    valid: bool
    sub: Optional[str] = None
    action: Optional[Enum] = None
    age: Optional[int] = None
    extra_data: Optional[Dict[Any, Any]] = None
    reason: Optional[str] = None


class JWTService:
    """Serviço para criação e validação de tokens JWT."""

    def __init__(
        self,
        config: "TokenConfig",
        logger: logging.Logger,
        action_enum: Type[Enum] = JWT_action,
    ) -> None:
        """Inicializa o serviço de tokens.

        Args:
            config (TokenConfig): Configurações validadas.
            logger: Logger do serviço.
            action_enum (Type[Enum]): Enum para ações do token.
        """
        self._config = config
        self._logger = logger
        self._action_enum = action_enum

        logger.debug("JWTService inicializado com algoritmo: %s", config.algorithm)


    def _ensure_jsonable(self, data: Any) -> Any:
        """Validate that data can be JSON-serialized without transforming it."""
        # Valida sem transformar, só garante serialização.
        try:
            json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise TokenCreationError("extra_data nao e serializavel em JSON") from exc
        return data

    def criar(
        self,
        action: Optional[Enum] = None,
        sub: Any = None,
        expires_in: int = 600,
        extra_data: Optional[Dict[Any, Any]] = None,
    ) -> str:
        """Create a JWT token with the provided claims."""
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

        agora = int(time.time())
        if action is None:
            action = self._action_enum.NO_ACTION

        if not isinstance(action, Enum):
            raise ValueError("action deve ser Enum")

        payload: Dict[str, Any] = {
            "sub": sub_str,
            "iat": agora,
            "nbf": agora,
            "action": action.name,
        }

        if expires_in > 0:
            payload["exp"] = agora + expires_in

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

        try:
            token = jwt.encode(
                payload=payload,
                key=self._config.secret_key,
                algorithm=self._config.algorithm,
            )
        except (TypeError, ValueError, jwt.InvalidKeyError) as e:
            self._logger.exception("Falha ao gerar JWT (encode). action=%s sub=%s", action.name, sub_str)
            raise TokenCreationError("Falha ao gerar token") from e
        except Exception as e:
            # Última barreira. Evita 500 “misterioso” sem log.
            self._logger.exception("Falha inesperada ao gerar JWT. action=%s sub=%s", action.name, sub_str)
            raise TokenCreationError("Falha inesperada ao gerar token") from e

        if isinstance(token, bytes):
            token = token.decode("utf-8")

        return token


    def validar(self, token: str) -> TokenVerificationResult:
        """Validate a JWT token and return a structured result."""
        if not isinstance(token, str) or not token.strip():
            return TokenVerificationResult(valid=False, reason="missing_token")

        try:
            payload = jwt.decode(
                token,
                key=self._config.secret_key,
                algorithms=[self._config.algorithm],
            )
        except jwt.ExpiredSignatureError as e:
            self._logger.info("JWT expirado")
            return TokenVerificationResult(valid=False, reason="expired")
        except jwt.InvalidSignatureError as e:
            self._logger.warning("Assinatura inválida no JWT")
            return TokenVerificationResult(valid=False, reason="bad_signature")
        except jwt.ImmatureSignatureError:
            self._logger.warning("JWT ainda não válido (nbf no futuro)")
            return TokenVerificationResult(valid=False, reason="immature")
        except jwt.InvalidTokenError as e:
            self._logger.warning("JWT inválido")
            return TokenVerificationResult(valid=False, reason="invalid")
        except Exception as e:
            self._logger.exception("Falha inesperada ao decodificar JWT")
            return TokenVerificationResult(valid=False, reason="internal_error")

        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub:
            return TokenVerificationResult(valid=False, reason="missing_sub")

        action_raw = payload.get("action", "NO_ACTION")
        if not isinstance(action_raw, str):
            return TokenVerificationResult(valid=False, reason="invalid_action")

        try:
            acao = self._action_enum[action_raw]
        except KeyError:
            return TokenVerificationResult(valid=False, reason="invalid_action")

        age = None
        if "iat" in payload:
            try:
                age = int(time.time()) - int(payload["iat"])
            except (TypeError, ValueError):
                return TokenVerificationResult(valid=False, reason="invalid_iat")

        extra_data = payload.get("extra_data")
        if extra_data is not None and not isinstance(extra_data, dict):
            return TokenVerificationResult(valid=False, reason="invalid_extra_data")

        return TokenVerificationResult(
            valid=True,
            sub=sub,
            action=acao,
            age=age,
            extra_data=extra_data,
        )


@dataclass(frozen=True)
class TokenConfig:
    """Configuracao do JWTService."""

    secret_key: str
    algorithm: str

    def __post_init__(self) -> None:
        if not isinstance(self.secret_key, str) or not self.secret_key.strip():
            raise ValueError("SECRET_KEY deve ser uma string valida")

        if not isinstance(self.algorithm, str) or not self.algorithm.strip():
            raise ValueError("JWT_ALGORITHM deve ser uma string valida")

        algoritmo = self.algorithm.strip().upper()
        object.__setattr__(self, "algorithm", algoritmo)
        if algoritmo != "HS256":
            raise ValueError(
                "JWT_ALGORITHM nao suportado. Use HS256 (sem chaves RSA configuradas)."
            )


def load_token_config_from_dict(app_config: Dict[str, Any]) -> TokenConfig:
    """Carrega configuracoes do JWTService a partir de um dict.

    Args:
        app_config: Dicionario de configuracao da aplicacao.

    Returns:
        TokenConfig: Configuracao validada do servico.
    """
    app_config.setdefault("JWT_ALGORITHM", "HS256")

    return TokenConfig(
        secret_key=app_config.get("SECRET_KEY"),
        algorithm=app_config.get("JWT_ALGORITHM"),
    )
