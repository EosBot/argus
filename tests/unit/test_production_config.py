"""Production configuration must fail closed on published development secrets."""

import pytest
from pydantic import ValidationError

from backend.core.config import Settings


def test_production_rejects_default_secrets() -> None:
    with pytest.raises(ValidationError, match="Segredos de produção"):
        Settings(
            environment="production",
            jwt_secret_key="change-me-in-production-32-char-min",
            postgres_password="argus_default",
            neo4j_password="argus_default",
            tor_control_password="argus_default",
        )


def test_production_accepts_explicit_strong_secrets() -> None:
    config = Settings(
        environment="production",
        jwt_secret_key="j" * 64,
        postgres_password="p" * 32,
        neo4j_password="n" * 32,
        tor_control_password="t" * 32,
    )

    assert config.environment == "production"
