"""API rate-limit partitioning and preflight tests."""

from starlette.requests import Request

from backend.core.middleware import RateLimitMiddleware


def _request(*, token: str | None = None, method: str = "GET", path: str = "/api/test") -> Request:
    headers = [] if token is None else [(b"authorization", f"Bearer {token}".encode())]
    return Request({
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "client": ("192.0.2.10", 1234),
        "scheme": "http",
        "server": ("test", 80),
    })


def test_authenticated_sessions_have_independent_hashed_keys():
    first = RateLimitMiddleware._get_rate_key(_request(token="token-a"))
    second = RateLimitMiddleware._get_rate_key(_request(token="token-b"))
    assert first != second
    assert "token-a" not in first
    assert "token-b" not in second
    assert first.startswith("192.0.2.10:token:")


def test_anonymous_requests_share_ip_partition():
    assert RateLimitMiddleware._get_rate_key(_request()) == "192.0.2.10:anonymous"
