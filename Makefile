.PHONY: help install install-dev test test-cov format lint type-check clean build upload docs dev check

help:
	@echo "JWTService - Makefile"
	@echo ""
	@echo "Available commands:"
	@echo "  make install        - Sync dependencies"
	@echo "  make install-dev    - Sync dev dependencies"
	@echo "  make test           - Run tests"
	@echo "  make test-cov       - Run tests with coverage"
	@echo "  make format         - Format code with black and isort"
	@echo "  make lint           - Lint code with flake8"
	@echo "  make type-check     - Type check with mypy"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make build          - Build package distribution"
	@echo "  make upload         - Upload to PyPI (requires credentials)"
	@echo "  make docs           - Documentation info"

install:
	uv sync

install-dev:
	uv sync --extra dev

test:
	uv run pytest -v

test-cov:
	uv run pytest -v --cov=jwtservice --cov-report=term-missing --cov-report=html

format:
	uv run black src/ tests/ examples/
	uv run isort src/ tests/ examples/

lint:
	uv run flake8 src/ tests/ --max-line-length=100 --extend-ignore=E203,W503,E501 --extend-select=B950

type-check:
	uv run mypy src/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

build: clean
	uv build

upload: build
	uv publish

docs:
	@echo "Documentation is in README.md"
	@echo "For more details, consult the docs folder if available"

dev: install-dev

check: format lint type-check test-cov
	@echo "All checks passed"
