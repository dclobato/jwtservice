# JWTService

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A lightweight JWT creation and validation service. It provides a small, explicit API for creating tokens with actions, expiration, and optional metadata.

## Features

- Simple service class for create/validate flows
- Action enum to tag token purpose (email validation, password reset, etc)
- Explicit configuration loader for dict-based settings
- Optional extra payload data
- Consistent error reasons for invalid tokens
- Built-in support for issuer (`iss`) and audience (`aud`) claims
- Flexible audience validation (string or list of strings)
- Optional per-token revocation with TTL based on `exp`

## Installation

### Makefile (Linux/macOS) vs Windows

- `Makefile` targets Linux/macOS.
- On Windows, use `Makefile.windows`:
  ```bash
  make -f Makefile.windows install-dev
  make -f Makefile.windows test
  make -f Makefile.windows check
  ```

### Core Install

```bash
uv add jwtservice
```

### For Development

```bash
uv sync --extra dev
```

## Quick Start

```python
import logging

from jwtservice import JWTService, JWTAction, load_token_config_from_dict

config = load_token_config_from_dict(
    {
        "SECRET_KEY": "my-super-secret-key",
        "JWTSERVICE_ALGORITHM": "HS256",
        "JWTSERVICE_ISSUER": "my-app",
        "JWTSERVICE_AUDIENCE": "my-api",  # Optional
    }
)

logger = logging.getLogger("jwt")
service = JWTService(config=config, logger=logger)

# Create token
token = service.criar(
    action=JWTAction.VALIDAR_EMAIL,
    sub="user@example.com",
    expires_in=600,
    extra_data={"flow": "signup"},
)

# Validate token
result = service.validar(token)
print(f"Valid: {result.valid}")
print(f"Status: {result.status}")
print(f"Subject: {result.sub}")
print(f"Action: {result.action}")
```

## Configuration Options

The service can be configured using a dictionary with the following keys:

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `SECRET_KEY` | `str` | Yes | - | Secret key for signing tokens |
| `JWTSERVICE_ALGORITHM` | `str` | No | `"HS256"` | Algorithm for signing (currently only HS256 supported) |
| `JWTSERVICE_ISSUER` | `str` | No | `"JWTService"` | Issuer claim (`iss`) for tokens |
| `JWTSERVICE_AUDIENCE` | `str` | No | `None` | Default audience claim (`aud`) for tokens |
| `JWTSERVICE_LEEWAY` | `int` | No | `0` | Leeway in seconds for time-based claims |
| `JWTSERVICE_RATELIMIT_CREATE` | `int` | No | `6000` | Max create operations per minute |
| `JWTSERVICE_RATELIMIT_VALIDATE` | `int` | No | `6000` | Max validate operations per minute |
| `JWTSERVICE_RATELIMIT` | `int` | No | `6000` | Legacy shared default for create/validate limits |

Set `JWTSERVICE_RATELIMIT_CREATE=0` or `JWTSERVICE_RATELIMIT_VALIDATE=0` to disable rate limiting
for that operation (a warning is logged on startup). If you only set `JWTSERVICE_RATELIMIT`, it
will be used as the default for both create and validate limits.

**See also**: `examples/rate_limit_usage.py` for a simple rate limiting demo.

## Audience Configuration

The audience claim provides an additional layer of security by specifying the intended recipient(s) of the token.

### Configuration Audience

Set a default audience in the configuration that will be applied to all tokens:

```python
config = load_token_config_from_dict(
    {
        "SECRET_KEY": "secret",
        "JWTSERVICE_ISSUER": "my-app",
        "JWTSERVICE_AUDIENCE": "my-api",  # Default audience
    }
)
```

### Per-Token Audience

Override the default audience when creating a token:

```python
# Create token with specific audience
token = service.criar(
    sub="user@example.com",
    audience="mobile-app",  # Overrides config audience
)
```

### Validating Audience

When validating, you can provide:
- A **string**: Token is valid if its audience matches exactly
- A **list of strings**: Token is valid if its audience matches ANY in the list

```python
# Validate with single audience
result = service.validar(token, audience="mobile-app")

# Validate with multiple possible audiences
result = service.validar(token, audience=["web-app", "mobile-app", "admin-panel"])
```

If no audience is provided during validation, the config audience is used (if set).

**See also**: `examples/audience_validation.py` for a comprehensive example demonstrating all audience validation scenarios.

## Custom Action Enum

If you want to replace the default action enum:

```python
import logging
from enum import Enum

from jwtservice import JWTService, load_token_config_from_dict


class MyAction(Enum):
    NO_ACTION = 0
    SIGNUP = 1
    LOGIN = 2


config = load_token_config_from_dict(
    {
        "SECRET_KEY": "my-super-secret-key",
        "JWTSERVICE_ALGORITHM": "HS256",
    }
)

logger = logging.getLogger("jwt")
service = JWTService(config=config, logger=logger, action_enum=MyAction)

token = service.criar(action=MyAction.SIGNUP, sub="user@example.com")
```

## Flask Integration (Optional)

You can still use Flask config dictionaries if you already have them:

```python
from jwtservice import load_token_config_from_dict

config = load_token_config_from_dict(app.config)
```

## Token Payload

The service stores the following fields:

- `sub`: subject identifier
- `iat`: issued at (UTC timestamp)
- `nbf`: not before (UTC timestamp)
- `exp`: expiration (only when `expires_in > 0`)
- `iss`: issuer (from config)
- `aud`: audience (from config or from call to `criar`, or None)
- `action`: enum name
- `jti`: unique token identifier (UUID v4)
- `extra_data`: optional dict

## Token Revocation

You can enable per-token revocation by configuring a revocation store. Revocations
are stored with a TTL based on the token `exp`, so they expire automatically.

Note: `RevocationStore` uses a `Protocol` (structural typing) so any backend that
implements `is_revoked` and `revoke` can be plugged in without inheritance. If you
prefer explicit inheritance and method enforcement at runtime, an `ABC` could be
used instead, but it would require backends to subclass it directly.

To add a new backend (e.g., Redis/Valkey), implement `is_revoked(jti)` and
`revoke(jti, ttl_seconds, metadata=None)`. For Redis, you can use `SET` with
`NX` + `EX` for atomic insert and `EXISTS` for checks:

```python
class RedisRevocationStore:
    def __init__(self, client):
        self._client = client

    def is_revoked(self, jti: str) -> bool:
        return bool(self._client.exists(f"revoked:{jti}"))

    def revoke(self, jti: str, ttl_seconds: int, metadata=None) -> bool:
        return bool(self._client.set(f"revoked:{jti}", "1", ex=ttl_seconds, nx=True))
```

```python
from jwtservice import InMemoryRevocationStore, JWTService

store = InMemoryRevocationStore()
service = JWTService(config=config, logger=logger, revocation_store=store)

token = service.criar(sub="user@example.com")
service.revogar(token, reason="logout")

result = service.validar(token)
print(result.status)  # "revoked"
```

For single-instance deployments you can use SQLite:

```python
from jwtservice import SQLiteRevocationStore, JWTService

store = SQLiteRevocationStore("revocations.db")
service = JWTService(config=config, logger=logger, revocation_store=store)
```

You can also revoke by jti/exp if you have those values in logs:

```python
service.revogar_jti(jti="...", exp=1710000000, reason="incident")
```

**See also**: `examples/revocation_usage.py` for in-memory and SQLite examples.

## Error Reasons

`JWTService.validar` returns a `TokenVerificationResult` with a `reason` when invalid:

- `missing_sub` - Token is missing the subject claim
- `missing_token` - No token provided or empty token
- `missing_jti` - Token is missing the jti claim (when revocation is enabled)
- `expired` - Token has expired
- `bad_signature` - Token signature is invalid
- `immature` - Token is not yet valid (nbf in future)
- `invalid_issuer` - Issuer claim doesn't match expected value
- `invalid_audience` - Audience claim doesn't match expected value(s)
- `invalid_iat` - Invalid issued at timestamp
- `invalid` - Token is malformed or invalid
- `invalid_action` - Action is not a valid enum value
- `revoked` - Token has been revoked

## Contributing

Contributions are welcome. See `CONTRIBUTING.md` and `INSTALLATION_GUIDE.md` for local setup and checks.

### Running Tests

```bash
uv sync --extra dev
uv run pytest
uv run pytest --cov=jwtservice --cov-report=html
```

## License

This project is licensed under the MIT License. See `LICENSE`.

## Author

**Daniel Correa Lobato**
- Website: [sites.lobato.org](https://sites.lobato.org)
- Email: daniel@lobato.org
