# Roadmap: Key Management and Algorithm Support

This roadmap documents potential next steps. These are **not implemented** today.

## Goals

- Add support for asymmetric algorithms (RS256/ES256)

## Proposed Features

### 1) Asymmetric Algorithms

Support RSA and ECDSA algorithms when public/private keys are provided in config.

### 2) Clock Skew

Allow a small leeway in `JWTService.validar` to tolerate clock drift.
