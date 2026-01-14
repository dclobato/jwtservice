# JWTService - Installation and First Steps

## Project Structure

```
jwtservice/
├── src/
│   └── jwtservice/           # Package source code
│       ├── __init__.py       # Public exports
│       └── core.py           # JWT service implementation
├── tests/
│   ├── conftest.py           # Pytest fixtures
│   └── unit/                 # Unit tests
├── examples/                 # Usage examples
├── pyproject.toml            # Project configuration
├── README.md                 # Main documentation
├── LICENSE                   # MIT license
├── CHANGELOG.md              # Release history
├── CONTRIBUTING.md           # Contributing guide
├── Makefile                  # Task automation (Linux/macOS)
└── Makefile.windows          # Task automation (Windows)
```

## Development Installation

### 1) Sync Dependencies with uv

```bash
cd jwtservice
```

### 2) Install Dependencies

```bash
# Core install
uv sync

# Development (pytest, mypy, etc)
uv sync --extra dev
```

### 3) Run Tests

```bash
# Basic tests
uv run pytest

# Coverage
uv run pytest --cov=jwtservice --cov-report=html

# Or use the Makefile
uv run make test
uv run make test-cov
```

### 4) Code Quality Checks

```bash
# Formatting
uv run make format

# Linting
uv run make lint

# Type checking
uv run make type-check

# All checks
uv run make check
```

## Testing the Package Locally

Create `test_local.py`:

```python
import logging

from jwtservice import JWTService, JWTAction, load_token_config_from_dict

config = load_token_config_from_dict(
    {
        "SECRET_KEY": "my-super-secret-key",
        "JWTSERVICE_ALGORITHM": "HS256",
        "JWTSERVICE_ISSUER": "my-app",
    }
)

logger = logging.getLogger("jwt")
service = JWTService(config=config, logger=logger)

token = service.criar(
    action=JWTAction.VALIDAR_EMAIL,
    sub="user@example.com",
    expires_in=600,
    extra_data={"flow": "signup"},
)

print(token)
print(service.validar(token))
```

Run:
```bash
uv run python test_local.py
```

## Publishing to PyPI

### 1) Update Version

Edit `src/jwtservice/__init__.py` and `pyproject.toml`:

```python
__version__ = "0.1.1"
```

### 2) Update CHANGELOG

Document changes in `CHANGELOG.md`.

### 3) Tag the Release

```bash
git add .
git commit -m "Release v0.1.1"
git tag v0.1.1
git push origin main --tags
```

### 4) Build and Upload

```bash
uv build
uv publish
```

### 5) Installation Test

```bash
uv init
uv add jwtservice
uv run python -c "from jwtservice import JWTService; print('OK')"
```

## Next Steps

1. Validate token creation/validation in your target app.
2. Add custom action enums where needed.
3. Publish when stable.

## Support

- Issues: https://github.com/dclobato/jwtservice/issues
- Email: daniel@lobato.org
- Website: https://sites.lobato.org
