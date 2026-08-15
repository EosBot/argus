"""Search parsing, URL encoding and provenance contracts."""

from unittest.mock import MagicMock

from argus_engine import search


ENGINE_HOST = "a" * 56 + ".onion"
TARGET_HOST = "b" * 56 + ".onion"
ENDPOINT = f"http://{ENGINE_HOST}/search?q={{query}}"


def response(html: str):
    value = MagicMock()
    value.status_code = 200
    value.text = html
    return value


def test_query_is_encoded_and_engine_provenance_is_preserved(monkeypatch):
    session = MagicMock()
    session.get.return_value = response(
        f'<a href="http://{TARGET_HOST}/case?id=1">Relevant result</a>'
    )
    monkeypatch.setattr(search, "get_tor_session", lambda: session)
    results = search.fetch_search_results(ENDPOINT, "registro civil & cartório", "TestEngine")
    requested_url = session.get.call_args.args[0]
    assert "registro+civil+%26+cart%C3%B3rio" in requested_url
    assert results[0]["source_engine"] == "TestEngine"
    assert results[0]["link"].startswith(f"http://{TARGET_HOST}")


def test_encoded_redirect_is_unwrapped_and_invalid_onions_are_rejected(monkeypatch):
    encoded = f"http%3A%2F%2F{TARGET_HOST}%2Fevidence"
    session = MagicMock()
    session.get.return_value = response(
        f'<a href="http://{ENGINE_HOST}/redirect?url={encoded}">Evidence result</a>'
        '<a href="http://abcdefghijklmnop.onion/legacy">Legacy onion</a>'
        '<a href="http://not-valid.onion/fake">Fake onion</a>'
    )
    monkeypatch.setattr(search, "get_tor_session", lambda: session)
    results = search.fetch_search_results(ENDPOINT, "query", "TestEngine")
    assert [item["link"] for item in results] == [f"http://{TARGET_HOST}/evidence"]


def test_credentials_in_result_url_are_rejected(monkeypatch):
    session = MagicMock()
    session.get.return_value = response(
        f'<a href="http://user:secret@{TARGET_HOST}/case">Credential URL</a>'
    )
    monkeypatch.setattr(search, "get_tor_session", lambda: session)
    assert search.fetch_search_results(ENDPOINT, "query", "TestEngine") == []
