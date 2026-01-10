# JWTService

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A lightweight JWT creation and validation service. It provides a small, explicit API for creating tokens with actions, expiration, and optional metadata.

## Features

- Simple service class for create/validate flows
- Action enum to tag token purpose (email validation, password reset, etc)
- Explicit configuration loader for dict-based settings
- Optional extra payload data
- Consistent error reasons for invalid tokens

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

from jwtservice import JWTService, JWT_action, load_token_config_from_dict

config = load_token_config_from_dict(
    {
        "SECRET_KEY": "minha-chave-super-secreta",
        "JWT_ALGORITHM": "HS256",
    }
)

logger = logging.getLogger("jwt")
service = JWTService(config=config, logger=logger)

# Create token
token = service.criar(
    action=JWT_action.VALIDAR_EMAIL,
    sub="usuario@example.com",
    expires_in=600,
    extra_data={"flow": "cadastro"},
)

# Validate token
result = service.validar(token)
```

## Custom Action Enum

If you want to replace the default action enum:

```python
import logging
from enum import Enum

from jwtservice import JWTService, load_token_config_from_dict


class MinhaAcao(Enum):
    NO_ACTION = 0
    CADASTRO = 1


config = load_token_config_from_dict(
    {
        "SECRET_KEY": "minha-chave-super-secreta",
        "JWT_ALGORITHM": "HS256",
    }
)

logger = logging.getLogger("jwt")
service = JWTService(config=config, logger=logger, action_enum=MinhaAcao)

token = service.criar(action=MinhaAcao.CADASTRO, sub="usuario@example.com")
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
- `action`: enum name
- `extra_data`: optional dict

## Error Reasons

`JWTService.validar` returns a `TokenVerificationResult` with a `reason` when invalid:

- `missing_sub`
- `expired`
- `bad_signature`
- `invalid`
- `invalid_action`
- `valueerror`

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
