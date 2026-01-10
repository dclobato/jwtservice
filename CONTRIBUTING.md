# Contributing Guide

Thanks for your interest in contributing to JWTService. This document covers contribution guidelines.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue including:

- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Python version and dependencies
- Relevant configuration
- Logs or error messages

### Suggesting Improvements

For feature requests:

- Describe the use case
- Explain how it would be used
- Consider existing alternatives
- Indicate whether you can implement it

### Pull Requests

1. **Fork the repo**
2. **Clone your fork**
   ```bash
   git clone https://github.com/your-user/jwtservice.git
   cd jwtservice
   ```
3. **Create a feature branch**
   ```bash
   git checkout -b feature/my-feature
   ```
4. **Set up the dev environment**
   ```bash
   uv sync --extra dev
   ```
5. **Make your changes**
   - Follow existing code style
   - Add tests for new features
   - Update documentation
6. **Run checks**
   ```bash
   uv run pytest
   uv run pytest --cov=jwtservice --cov-report=html
   uv run black src/ tests/
   uv run isort src/ tests/
   uv run mypy src/
   ```
7. **Commit**
   ```bash
   git add .
   git commit -m "Clear change description"
   ```
8. **Push**
   ```bash
   git push origin feature/my-feature
   ```
9. **Open a Pull Request**

## Code Standards

### Style

- Follow PEP 8 with line length 100
- Use Black for formatting
- Use isort for import ordering
- Type hints on all public functions

### Tests

- Unit tests for each feature
- Minimum coverage 85%
- Use pytest fixtures where appropriate

### Documentation

- Google-style docstrings
- Examples in docstrings when useful
- Update `README.md` for user-visible changes
- Add a `CHANGELOG.md` entry

### Commits

Commit messages should:
- Use imperative mood
- Be <= 72 characters on the first line
- Stay consistent in language within a PR

Example:
```
Add token revocation helper

Introduce a simple helper for invalidating tokens
based on jti tracking.
```

## Conventional Commits Guide

All commits in this project must follow this format:

```
<type>(<scope>): <short summary>
<blank line>
[optional longer description]
<blank line>
[optional BREAKING CHANGE: describe the breaking change]
```

### Commit Types

- **feat**: Introduce a new feature.
- **fix**: Fix a bug.
- **docs**: Documentation-only changes.
- **style**: Formatting or style changes that do **not** affect behavior
- **refactor**: Code changes that **do not** fix bugs or **add features**
- **perf**: Performance improvements.
- **test**: Add or fix tests.
- **build**: Changes that affect the build system or external dependencies.
- **ci**: Changes to CI configuration or scripts.
- **chore**: Changes that **do not** affect production code
- **revert**: Revert a previous commit.

### Writing a Good Summary

- Keep it short and direct (max 72 characters).
- Use infinitive verbs: "add", "fix", "update", etc.
- Always describe **what** changed, **where**, and if needed, **why**.

### Examples

```bash
feat(core): add jti claim support
fix(validation): handle missing iat

docs: update README with usage instructions
refactor: improve token decoding flow
chore: update project dependencies
feat!: require explicit audience

BREAKING CHANGE: audience is now required
```

## Project Structure

```
jwtservice/
├── src/
│   └── jwtservice/
│       ├── __init__.py
│       └── core.py
├── tests/
│   └── unit/
├── examples/
```

## Review Process

Pull requests go through:

1. **Automated checks**
   - Tests must pass
   - Coverage must not decrease
   - Black and isort must be applied
   - mypy must be clean
2. **Code review**
   - At least one maintainer approval
   - Discussion is welcome
3. **Merge**
   - Squash and merge for a clean history
   - Release notes updated

## Versioning

We follow Semantic Versioning:

- **MAJOR**: breaking changes
- **MINOR**: backward-compatible features
- **PATCH**: backward-compatible fixes

## License

By contributing, you agree that your contributions are licensed under the MIT License.

## Questions?

Open an issue or email daniel@lobato.org.

Thanks for contributing.
