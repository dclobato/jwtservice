# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
- TBD

## [1.0.2]
- Add English wrapper methods in `JWTService`: `create`, `validate`, `revoke`, and `revoke_jti`
- Add tests validating wrapper behavior parity with `criar`, `validar`, `revogar`, and `revogar_jti`
- Update README and installation guide examples to include English aliases

## [1.0.1]
- Expose `jti` in `TokenVerificationResult` for `valid` and `revoked` statuses
- Add tests covering `jti` in validation and revoked responses
- Document `jti` exposure in README

## [0.1.0]
- Initial release

[Unreleased]: https://github.com/dclobato/jwtservice/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/dclobato/jwtservice/releases/tag/v1.0.2
[1.0.1]: https://github.com/dclobato/jwtservice/releases/tag/v1.0.1
[0.1.0]: https://github.com/dclobato/jwtservice/releases/tag/v0.1.0
