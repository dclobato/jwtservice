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
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Type, Union

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

        if self._revocation_ttl_max is not None:
            if not isinstance(self._revocation_ttl_max, int) or self._revocation_ttl_max <= 0:
                raise ValueError("revocation_ttl_max deve ser um inteiro positivo")

        logger.debug("JWTService inicializado com algoritmo: %s", config.algorithm)

    def _get_now(self) -> int:
        return int(time.time())

    def _apply_ttl_cap(self, ttl_seconds: int) -> int:
        if self._revocation_ttl_max is None:
            return ttl_seconds
        return min(ttl_seconds, self._revocation_ttl_max)

    def _ensure_jsonable(self, data: Any) -> Any:
        """Valida que os dados podem ser serializados em JSON sem transformá-los."""
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
        audience: Optional[str] = None,
        jti: Optional[str] = None,
        extra_data: Optional[Dict[Any, Any]] = None,
    ) -> str:
        """Cria um token JWT com as claims fornecidas.

        Args:
            action: Ação do token (usa NO_ACTION se não fornecido)
            sub: Subject identifier (identificador do usuário/entidade)
            expires_in: Tempo de expiração em segundos (padrão: 600)
            audience: Audience do token (string)
            extra_data: Dados extras para incluir no payload
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
            token: Token JWT a ser validado
            audience: Audience opcional para validar. Pode ser uma string ou lista de strings.
                     Se uma lista for fornecida, o token é válido se seu audience corresponder
                     a QUALQUER um dos valores na lista.
        """
        if not isinstance(token, str) or not token.strip():
            return TokenVerificationResult(valid=False, status="invalid", reason="missing_token")

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
        """Revoga um token JWT armazenando seu jti com TTL."""
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

        ttl_seconds = exp - self._get_now()
        if ttl_seconds <= 0:
            return False

        ttl_seconds = self._apply_ttl_cap(ttl_seconds)
        metadata = {"reason": reason} if reason else None
        return self._revocation_store.revoke(jti, ttl_seconds, metadata)

    def revogar_jti(self, jti: str, exp: int, reason: Optional[str] = None) -> bool:
        """Revoga um jti conhecido usando o exp fornecido."""
        if self._revocation_store is None:
            self._logger.warning("Revogacao solicitada sem revocation_store configurado")
            return False

        if not isinstance(jti, str) or not jti.strip():
            return False
        if not isinstance(exp, int):
            return False

        ttl_seconds = exp - self._get_now()
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
    )
