from backend.features.research import redact_sensitive_payload, redact_sensitive_text


def test_redacts_labelled_passwords_and_tokens() -> None:
    text, count = redact_sensitive_text("user=a password=hunter22 token:abcd1234")

    assert "hunter22" not in text
    assert "abcd1234" not in text
    assert count == 2


def test_redacts_combo_list_but_keeps_account_for_correlation() -> None:
    text, count = redact_sensitive_text("analyst@example.org:SecretPass9")

    assert text == "analyst@example.org:[REDACTED_CREDENTIAL]"
    assert count == 1


def test_does_not_change_regular_source_text() -> None:
    text, count = redact_sensitive_text(
        "Relatório menciona vazamento sem amostra de credenciais."
    )

    assert text.endswith("credenciais.")
    assert count == 0


def test_nested_payload_secret_fields_are_redacted() -> None:
    clean, count = redact_sensitive_payload({
        "data": [{"password": "value", "name": "safe"}],
        "Authorization": "Bearer secret",
    })

    assert clean["data"][0]["password"] == "[REDACTED_CREDENTIAL]"
    assert clean["Authorization"] == "[REDACTED_CREDENTIAL]"
    assert count == 2
