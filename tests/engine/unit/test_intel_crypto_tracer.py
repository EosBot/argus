"""Tests for CryptoTracer with TTL cache."""

import time
from unittest.mock import MagicMock, patch

import pytest

from argus_engine.intel.crypto_tracer import CryptoTracer, _TTLCache


class TestTTLCache:
    """Test suite for _TTLCache."""

    def test_set_and_get(self):
        """Cache should store and retrieve values."""
        cache = _TTLCache(ttl=60)
        cache.set("test_value", "arg1", "arg2")
        hit, value = cache.get("arg1", "arg2")
        assert hit is True
        assert value == "test_value"

    def test_cache_miss(self):
        """Cache should return miss for missing keys."""
        cache = _TTLCache(ttl=60)
        hit, value = cache.get("nonexistent")
        assert hit is False
        assert value is None

    def test_cache_expiry(self):
        """Cache entries should expire after TTL."""
        cache = _TTLCache(ttl=1)
        cache.set("value", "key")
        time.sleep(1.1)
        hit, value = cache.get("key")
        assert hit is False
        assert value is None

    def test_clear(self):
        """clear should remove all entries."""
        cache = _TTLCache(ttl=60)
        cache.set("v1", "k1")
        cache.set("v2", "k2")
        cache.clear()
        hit, _ = cache.get("k1")
        assert hit is False

    def test_different_args_different_keys(self):
        """Different args should produce different cache entries."""
        cache = _TTLCache(ttl=60)
        cache.set("v1", "a", "b")
        cache.set("v2", "a", "c")
        hit1, val1 = cache.get("a", "b")
        hit2, val2 = cache.get("a", "c")
        assert hit1 and val1 == "v1"
        assert hit2 and val2 == "v2"

    def test_kwargs_in_key(self):
        """kwargs should be part of cache key."""
        cache = _TTLCache(ttl=60)
        cache.set("v1", "a", key="val1")
        hit, value = cache.get("a", key="val1")
        assert hit is True
        assert value == "v1"


class TestCryptoTracer:
    """Test suite for CryptoTracer."""

    def test_init(self):
        """CryptoTracer should initialize with default values."""
        tracer = CryptoTracer()
        assert tracer._etherscan_key == ""
        assert tracer._blockchair_key == ""
        assert tracer._timeout == 15

    def test_init_with_keys(self):
        """CryptoTracer should accept API keys."""
        tracer = CryptoTracer(
            etherscan_api_key="test-etherscan",
            blockchair_api_key="test-blockchair",
        )
        assert tracer._etherscan_key == "test-etherscan"
        assert tracer._blockchair_key == "test-blockchair"

    def test_proxy_is_applied_to_both_http_schemes(self):
        tracer = CryptoTracer(proxy_url="socks5h://tor:9050")
        assert tracer._session.proxies == {
            "http": "socks5h://tor:9050",
            "https": "socks5h://tor:9050",
        }

    def test_trace_btc_empty_address(self):
        """trace_btc should handle empty address."""
        tracer = CryptoTracer()
        result = tracer.trace_btc("")
        assert result["address"] == ""
        assert result["transactions"] == []

    def test_trace_eth_empty_address(self):
        """trace_eth should handle empty address."""
        tracer = CryptoTracer()
        result = tracer.trace_eth("")
        assert result["address"] == ""
        assert result["transactions"] == []

    def test_trace_btc_with_mock(self):
        """trace_btc should use mocked session."""
        tracer = CryptoTracer()
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": {
                    "transactions": [
                        {
                            "hash": "abc123",
                            "time": "2024-01-01",
                            "balance_change": 100000,
                            "fee": 1000,
                            "block_id": 800000,
                            "outputs": [["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 50000]],
                            "inputs": [["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 100000]],
                        }
                    ]
                }
            }
        }
        mock_response.raise_for_status = MagicMock()
        mock_session.get.return_value = mock_response
        tracer._session = mock_session

        result = tracer.trace_btc("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert result["address"] == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        assert result["chain"] == "BTC"
        assert len(result["transactions"]) >= 1

    def test_trace_eth_with_mock(self):
        """trace_eth should use mocked session."""
        tracer = CryptoTracer()
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "1",
            "result": [
                {
                    "hash": "0xabc123",
                    "timeStamp": "1700000000",
                    "from": "0x1111",
                    "to": "0x2222",
                    "value": "1000000000000000000",
                    "gas": "21000",
                    "gasPrice": "20000000000",
                    "txreceipt_status": "1",
                    "isError": "0",
                    "blockNumber": "18000000",
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()
        mock_session.get.return_value = mock_response
        tracer._session = mock_session

        result = tracer.trace_eth("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08")
        assert result["chain"] == "ETH"
        assert len(result["transactions"]) >= 1

    def test_visualize_flow_empty(self):
        """visualize_flow should handle empty transactions."""
        tracer = CryptoTracer()
        result = tracer.visualize_flow([])
        assert result["nodes"] == []
        assert result["edges"] == []
        assert result["meta"]["total"] == 0

    def test_visualize_flow_with_data(self):
        """visualize_flow should build graph data."""
        tracer = CryptoTracer()
        transactions = [
            {
                "sender": "addr1",
                "outputs": [{"recipient": "addr2", "value": 1.5}],
            }
        ]
        result = tracer.visualize_flow(transactions)
        assert len(result["nodes"]) >= 2
        assert len(result["edges"]) >= 1

    def test_identify_exchanges_empty(self):
        """identify_exchanges should handle empty address."""
        tracer = CryptoTracer()
        result = tracer.identify_exchanges("")
        assert result == []

    def test_identify_exchanges_known(self):
        """identify_exchanges should find known exchange addresses."""
        tracer = CryptoTracer()
        # Binance address from the known list
        result = tracer.identify_exchanges("1Pzaqw98PeRfyHypfqyEgg5yycJRXu4Uk")
        assert "binance" in result

    def test_calculate_risk_empty_history(self):
        """calculate_risk should return 0 for empty history."""
        tracer = CryptoTracer()
        result = tracer.calculate_risk("addr", [])
        assert result == 0.0

    def test_calculate_risk_with_history(self):
        """calculate_risk should compute risk score."""
        tracer = CryptoTracer()
        history = [
            {"value": 100, "from": "a", "to": "b", "is_error": "0"},
            {"value": 200, "from": "b", "to": "c", "is_error": "0"},
        ]
        result = tracer.calculate_risk("addr", history)
        assert 0.0 <= result <= 1.0

    def test_clear_cache(self):
        """clear_cache should clear the cache."""
        tracer = CryptoTracer()
        tracer._cache.set("value", "key")
        tracer.clear_cache()
        hit, _ = tracer._cache.get("key")
        assert hit is False

    def test_shorten_addr(self):
        """_shorten_addr should shorten addresses."""
        result = CryptoTracer._shorten_addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert "..." in result
        assert result.startswith("1A1zP1")

    def test_shorten_addr_short(self):
        """_shorten_addr should not shorten short addresses."""
        result = CryptoTracer._shorten_addr("abc")
        assert result == "abc"

    def test_empty_result(self):
        """_empty_result should return correct structure."""
        result = CryptoTracer._empty_result("test_addr")
        assert result["address"] == "test_addr"
        assert result["transactions"] == []
        assert result["peers"] == []
        assert result["exchange"] == []

    def test_context_manager(self):
        """CryptoTracer should work as context manager."""
        with CryptoTracer() as tracer:
            assert tracer is not None

    def test_close(self):
        """close should close the session."""
        tracer = CryptoTracer()
        tracer._session = MagicMock()
        tracer.close()
        tracer._session.close.assert_called_once()
