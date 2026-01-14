"""Example demonstrating audience validation with single and multiple audiences."""

import logging

from jwtservice import JWTAction, JWTService, load_token_config_from_dict


def main() -> None:
    # Configure logging to see validation messages
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("jwt")

    # Create service without default audience
    config = load_token_config_from_dict(
        {
            "SECRET_KEY": "my-super-secret-key",
            "JWTSERVICE_ALGORITHM": "HS256",
            "JWTSERVICE_ISSUER": "my-app",
        }
    )
    service = JWTService(config=config, logger=logger)

    print("=" * 60)
    print("JWT Audience Validation Examples")
    print("=" * 60)

    # Create a token for the mobile app
    token = service.criar(
        action=JWTAction.NO_ACTION,
        sub="user@example.com",
        expires_in=3600,
        audience="mobile-app",
    )

    print(f"\n1. Created token with audience: 'mobile-app'")
    print(f"   Token: {token[:50]}...")

    # Example 1: Validate with exact match (single string)
    print("\n2. Validating with single audience 'mobile-app' (exact match)")
    result = service.validar(token, audience="mobile-app")
    print(f"   Valid: {result.valid}")
    print(f"   Audience: {result.aud}")

    # Example 2: Validate with wrong audience (single string)
    print("\n3. Validating with single audience 'web-app' (no match)")
    result = service.validar(token, audience="web-app")
    print(f"   Valid: {result.valid}")
    print(f"   Reason: {result.reason}")

    # Example 3: Validate with list containing the audience
    print("\n4. Validating with list ['web-app', 'mobile-app', 'admin-panel']")
    result = service.validar(token, audience=["web-app", "mobile-app", "admin-panel"])
    print(f"   Valid: {result.valid}")
    print(f"   Audience: {result.aud}")
    print(f"   ✓ Token is valid because 'mobile-app' is in the list")

    # Example 4: Validate with list NOT containing the audience
    print("\n5. Validating with list ['web-app', 'admin-panel']")
    result = service.validar(token, audience=["web-app", "admin-panel"])
    print(f"   Valid: {result.valid}")
    print(f"   Reason: {result.reason}")
    print(f"   ✗ Token is invalid because 'mobile-app' is NOT in the list")

    # Example 5: Token without audience, validated without audience
    print("\n" + "=" * 60)
    print("6. Token created without audience")
    token_no_aud = service.criar(
        sub="user@example.com",
        expires_in=3600,
    )
    result = service.validar(token_no_aud)
    print(f"   Valid: {result.valid}")
    print(f"   Audience: {result.aud}")

    # Example 6: Using config default audience
    print("\n" + "=" * 60)
    print("7. Using default audience from config")
    config_with_aud = load_token_config_from_dict(
        {
            "SECRET_KEY": "my-super-secret-key",
            "JWTSERVICE_ALGORITHM": "HS256",
            "JWTSERVICE_ISSUER": "my-app",
            "JWTSERVICE_AUDIENCE": "api-service",
        }
    )
    service_with_aud = JWTService(config=config_with_aud, logger=logger)

    # Token will automatically get the config audience
    token_default = service_with_aud.criar(
        sub="user@example.com",
        expires_in=3600,
    )
    print(f"   Token created with default audience from config")

    result = service_with_aud.validar(token_default)
    print(f"   Valid: {result.valid}")
    print(f"   Audience: {result.aud}")

    # Can still validate with list of audiences
    result = service_with_aud.validar(token_default, audience=["api-service", "backup-service"])
    print(f"   Valid with list ['api-service', 'backup-service']: {result.valid}")

    print("\n" + "=" * 60)
    print("Summary:")
    print("  - Config audience: Must be a string")
    print("  - Token audience: Must be a string")
    print("  - Validation audience: Can be a string OR list of strings")
    print("  - With list: Token is valid if its aud matches ANY in the list")
    print("=" * 60)


if __name__ == "__main__":
    main()
