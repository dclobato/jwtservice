# Repository Guidelines

## Project Structure & Module Organization
- `src/jwtservice/` holds the library code (core JWT service and helpers).
- `tests/` contains unit tests (see `tests/unit/`).
- `examples/` includes runnable usage samples.
- `README.md` documents usage and configuration.
- `BACKEND_GUIDE.md` explains how maintainers add actions or algorithms.
- `ROADMAP.md` outlines potential future work.

## Build, Test, and Development Commands
- `uv sync --extra dev` installs dev dependencies locally.
- `make install-dev` does the same via the Makefile.
- `uv run pytest -v` runs the test suite.
- `uv run pytest --cov=jwtservice --cov-report=html` generates coverage output in `htmlcov/`.
- `make format` runs `black` and `isort` via `uv run`.
- `make lint` runs `flake8` via `uv run` with max line length 100.
- `make type-check` runs `mypy` via `uv run`.
- `make build` builds the package distribution via `uv build`.
- On Windows, use `Makefile.windows` (e.g., `make -f Makefile.windows check`).

## Coding Style & Naming Conventions
- Python style follows PEP 8 with a 100-character line length.
- Format with `black` and `isort`; lint with `flake8`; type-check with `mypy`.
- Public functions should include type hints and Google-style docstrings.
- Test files follow `test_*.py` and test functions use `test_*`.

## Testing Guidelines
- Framework: `pytest` with `pytest-cov`.
- Coverage target: keep at or above 85% where feasible.
- Use fixtures for shared setup and prefer small, focused unit tests.
- Run full checks with `make check` (format, lint, type-check, coverage).

## Commit & Pull Request Guidelines
- Commit messages should be imperative, <= 72 characters on the first line, and written in either Portuguese or English (stay consistent per PR).
- Example:
  ```
  Add token validation metrics
  ```
- PRs should describe changes, link related issues when available, and include tests/docs updates (e.g., `README.md`, `CHANGELOG.md`) for user-facing behavior.
- Ensure formatting, linting, type checks, and tests pass before opening a PR.

## Configuration Tips
- Required settings: `SECRET_KEY`.
- Only HS256 is supported by default; changes require updates in `TokenConfig`.
