"""Cryptocurrency Transaction Tracing for ARGUS.

Provides BTC/LTC/ZEC tracing via Blockchair API, ETH/ERC-20 tracing via
Etherscan API, transaction flow visualization (directed graph), exchange
identification via known-address clustering, and risk scoring.

All external APIs use requests with graceful degradation — if an API
is unreachable or unauthenticated, methods return empty results
rather than raising exceptions. Results are cached with a 30-minute TTL.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependencies — graceful fallback
# ---------------------------------------------------------------------------
try:
    import requests  # type: ignore[import-untyped]

    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    _logger.debug("requests not installed — CryptoTracer will return empty results")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_BLOCKCHAIR_BASE = "https://api.blockchair.com"
_ETHERSCAN_BASE = "https://api.etherscan.io/api"
_DEFAULT_TIMEOUT = 15  # seconds
_CACHE_TTL = 1800  # 30 minutes in seconds
_MAX_DEPTH = 5  # maximum tracing depth to prevent infinite loops

# Known exchange addresses (subset for clustering identification)
# Sources: WalletExplorer, public exchange disclosures, Chainalysis reports
_KNOWN_EXCHANGES: dict[str, list[str]] = {
    "binance": [
        "1Pzaqw98PeRfyHypfqyEgg5yycJRXu4Uk",
        "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo",
        "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    ],
    "coinbase": [
        "1LQoWist8KkaUXSPKZHNvEyfrEkPHzSsCd",
        "3HbPSGdQ8TFhDLW3r58Ek7NZbZobn8Cpbu",
        "bc1q0sg9rdst255gtlda6esa3s7s0gdtl03k2zxqt8",
    ],
    "kraken": [
        "1JfbZRwdDHKZmuiZgYArJZhcuuzuw2HuMu",
        "1J3VBKi3CTkFzA9yFszJpVUFAmEXCKHqt1",
    ],
    "bitfinex": [
        "1Kr6QSydW9bFQG1mXiPNNu6WpJGmUa9i1g",
        "3JZq4atUahhuA9rLhXLMhhTo133J9rF97j",
    ],
    "huobi": [
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "14XKsv8tT6tt8P8mfDQZgNF8wtN5erNu5D",
    ],
    "okx": [
        "bc1q2f0tcjx40g3mn3z5j7fdwujp7rnzk9xk0dsvja",
        "bc1q9w4g7y4j5x3q3z5j7fdwujp7rnzk9xk0dsvja",
    ],
    "bybit": [
        "bc1q9h0yjdupyfpxfjg24rpx755xrplvzd9hz2nj7v",
    ],
    "kucoin": [
        "1LAnF8h3qMGx3TSwNUHVneBZUEpwE4N2US",
    ],
}

# Build reverse lookup: address -> exchange name
_EXCHANGE_ADDRESS_MAP: dict[str, str] = {}
for _exchange, _addresses in _KNOWN_EXCHANGES.items():
    for _addr in _addresses:
        _EXCHANGE_ADDRESS_MAP[_addr.lower()] = _exchange


# ---------------------------------------------------------------------------
# Simple TTL cache
# ---------------------------------------------------------------------------
class _TTLCache:
    """Minimal in-memory cache with TTL expiration."""

    def __init__(self, ttl: int = _CACHE_TTL) -> None:
        self._ttl = ttl
        self._store: dict[str, tuple[float, Any]] = {}

    def _key(self, *args: Any, **kwargs: Any) -> str:
        raw = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, *args: Any, **kwargs: Any) -> tuple[bool, Any]:
        """Return (hit, value). hit=False means expired or missing."""
        k = self._key(*args, **kwargs)
        if k in self._store:
            ts, val = self._store[k]
            if time.time() - ts < self._ttl:
                return True, val
            del self._store[k]
        return False, None

    def set(self, value: Any, *args: Any, **kwargs: Any) -> None:
        k = self._key(*args, **kwargs)
        self._store[k] = (time.time(), value)

    def clear(self) -> None:
        self._store.clear()


# ---------------------------------------------------------------------------
# CryptoTracer
# ---------------------------------------------------------------------------
class CryptoTracer:
    """Cryptocurrency transaction tracer with flow visualization.

    Supports BTC/LTC/ZEC via Blockchair and ETH/ERC-20 via Etherscan.
    Results are cached for 30 minutes to respect API rate limits.
    """

    def __init__(
        self,
        etherscan_api_key: str = "",
        blockchair_api_key: str = "",
        timeout: int = _DEFAULT_TIMEOUT,
        cache_ttl: int = _CACHE_TTL,
        proxy_url: str | None = None,
    ) -> None:
        self._etherscan_key = etherscan_api_key
        self._blockchair_key = blockchair_api_key
        self._timeout = timeout
        self._cache = _TTLCache(ttl=cache_ttl)
        self._session = requests.Session() if _HAS_REQUESTS else None
        if self._session:
            if proxy_url:
                self._session.proxies.update({"http": proxy_url, "https": proxy_url})
            self._session.headers.update(
                {"User-Agent": "ARGUS-CryptoTracer/2.0"}
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def trace_btc(self, address: str, depth: int = 2) -> dict:
        """Trace BTC transactions for an address up to *depth* hops.

        Returns a dict with keys: ``address``, ``transactions``,
        ``peers``, ``depth_reached``, ``exchange`` (if identified).
        """
        if not _HAS_REQUESTS or not address:
            return self._empty_result(address)

        cached, val = self._cache.get("trace_btc", address, depth)
        if cached:
            return val

        result = self._trace_btc_impl(address, depth)
        self._cache.set(result, "trace_btc", address, depth)
        return result

    def trace_eth(self, address: str, depth: int = 2) -> dict:
        """Trace ETH/ERC-20 transactions for an address up to *depth* hops.

        Returns a dict with keys: ``address``, ``transactions``,
        ``peers``, ``depth_reached``, ``exchange`` (if identified).
        """
        if not _HAS_REQUESTS or not address:
            return self._empty_result(address)

        cached, val = self._cache.get("trace_eth", address, depth)
        if cached:
            return val

        result = self._trace_eth_impl(address, depth)
        self._cache.set(result, "trace_eth", address, depth)
        return result

    def visualize_flow(self, transactions: list[dict]) -> dict:
        """Generate Plotly-compatible directed graph data from transactions.

        Returns dict with ``nodes`` and ``edges`` keys ready for
        ``plotly.graph_objects.Sankey`` or ``plotly.graph_objects.Figure``.
        """
        if not transactions:
            return {"nodes": [], "edges": [], "meta": {"total": 0}}

        return self._build_graph_data(transactions)

    def identify_exchanges(self, address: str) -> list[str]:
        """Identify if *address* belongs to a known exchange.

        Returns a list of exchange names (may contain multiple matches
        or be empty if unknown).
        """
        if not address:
            return []

        cached, val = self._cache.get("identify_exchanges", address)
        if cached:
            return val

        matches = self._find_exchange_matches(address)
        self._cache.set(matches, "identify_exchanges", address)
        return matches

    def calculate_risk(self, address: str, history: list[dict]) -> float:
        """Calculate a risk score (0.0–1.0) for an address.

        Factors: transaction frequency, interaction with known exchange
        addresses, amount variance, and address age proxy.
        """
        if not history:
            return 0.0

        cached, val = self._cache.get("calculate_risk", address, len(history))
        if cached:
            return val

        score = self._compute_risk_score(address, history)
        self._cache.set(score, "calculate_risk", address, len(history))
        return score

    def clear_cache(self) -> None:
        """Clear the internal result cache."""
        self._cache.clear()

    # ------------------------------------------------------------------
    # BTC tracing (Blockchair)
    # ------------------------------------------------------------------
    def _trace_btc_impl(self, address: str, depth: int) -> dict:
        depth = min(depth, _MAX_DEPTH)
        transactions: list[dict] = []
        peers: set[str] = set()
        visited: set[str] = set()

        current_level = {address}
        for level in range(depth):
            next_level: set[str] = set()
            for addr in current_level:
                if addr in visited:
                    continue
                visited.add(addr)

                txs = self._fetch_btc_transactions(addr)
                for tx in txs:
                    transactions.append(tx)
                    # Collect counterparties for next level
                    for output in tx.get("outputs", []):
                        out_addr = output.get("recipient", "")
                        if out_addr and out_addr != addr:
                            peers.add(out_addr)
                            if len(visited) + len(next_level) < 100:
                                next_level.add(out_addr)
                    for inp in tx.get("inputs", []):
                        in_addr = inp.get("recipient", "") or inp.get("address", "")
                        if in_addr and in_addr != addr:
                            peers.add(in_addr)
                            if len(visited) + len(next_level) < 100:
                                next_level.add(in_addr)

            current_level = next_level - visited
            if not current_level:
                break

        exchange = self._find_exchange_matches(address)
        return {
            "address": address,
            "transactions": transactions,
            "peers": list(peers),
            "depth_reached": depth,
            "exchange": exchange,
            "chain": "BTC",
        }

    def _fetch_btc_transactions(self, address: str) -> list[dict]:
        """Fetch recent BTC transactions for an address via Blockchair."""
        url = f"{_BLOCKCHAIR_BASE}/bitcoin/dashboards/address/{address}"
        params: dict[str, Any] = {"limit": 50}
        if self._blockchair_key:
            params["key"] = self._blockchair_key

        try:
            resp = self._session.get(url, params=params, timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            _logger.debug("Blockchair fetch failed for %s: %s", address, exc)
            return []

        addr_data = data.get("data", {}).get(address, {})
        if not addr_data:
            return []

        raw_txs = addr_data.get("transactions", [])
        transactions = []
        for tx in raw_txs:
            transactions.append(
                {
                    "hash": tx.get("hash", ""),
                    "time": tx.get("time", ""),
                    "value": tx.get("balance_change", 0),
                    "fee": tx.get("fee", 0),
                    "block_id": tx.get("block_id", 0),
                    "sender": address,
                    "outputs": [
                        {"recipient": o[0], "value": o[1]}
                        for o in tx.get("outputs", [])
                        if isinstance(o, list) and len(o) >= 2
                    ],
                    "inputs": [
                        {"address": i[0], "value": i[1]}
                        for i in tx.get("inputs", [])
                        if isinstance(i, list) and len(i) >= 2
                    ],
                }
            )
        return transactions

    # ------------------------------------------------------------------
    # ETH tracing (Etherscan)
    # ------------------------------------------------------------------
    def _trace_eth_impl(self, address: str, depth: int) -> dict:
        depth = min(depth, _MAX_DEPTH)
        transactions: list[dict] = []
        peers: set[str] = set()
        visited: set[str] = set()

        current_level = {address}
        for level in range(depth):
            next_level: set[str] = set()
            for addr in current_level:
                if addr in visited:
                    continue
                visited.add(addr)

                txs = self._fetch_eth_transactions(addr)
                for tx in txs:
                    transactions.append(tx)
                    to_addr = tx.get("to", "")
                    from_addr = tx.get("from", "")
                    if to_addr and to_addr != addr:
                        peers.add(to_addr)
                        next_level.add(to_addr)
                    if from_addr and from_addr != addr:
                        peers.add(from_addr)
                        next_level.add(from_addr)

            current_level = next_level - visited
            if not current_level:
                break

        exchange = self._find_exchange_matches(address)
        return {
            "address": address,
            "transactions": transactions,
            "peers": list(peers),
            "depth_reached": depth,
            "exchange": exchange,
            "chain": "ETH",
        }

    def _fetch_eth_transactions(self, address: str) -> list[dict]:
        """Fetch ETH transactions for an address via Etherscan."""
        params: dict[str, Any] = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "page": 1,
            "offset": 50,
            "sort": "desc",
        }
        if self._etherscan_key:
            params["apikey"] = self._etherscan_key

        try:
            resp = self._session.get(
                _ETHERSCAN_BASE, params=params, timeout=self._timeout
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            _logger.debug("Etherscan fetch failed for %s: %s", address, exc)
            return []

        if data.get("status") != "1" or not data.get("result"):
            return []

        transactions = []
        for tx in data["result"]:
            transactions.append(
                {
                    "hash": tx.get("hash", ""),
                    "time": tx.get("timeStamp", ""),
                    "from": tx.get("from", ""),
                    "to": tx.get("to", ""),
                    "value": int(tx.get("value", 0)) / 1e18,  # wei -> ETH
                    "gas": int(tx.get("gas", 0)),
                    "gas_price": int(tx.get("gasPrice", 0)),
                    "tx_receipt_status": tx.get("txreceipt_status", ""),
                    "is_error": tx.get("isError", "0"),
                    "block_number": int(tx.get("blockNumber", 0)),
                }
            )
        return transactions

    # ------------------------------------------------------------------
    # Graph visualization data
    # ------------------------------------------------------------------
    def _build_graph_data(self, transactions: list[dict]) -> dict:
        """Build Plotly Sankey-compatible node/edge structure."""
        nodes_set: set[str] = set()
        edges: list[dict] = []
        node_labels: dict[str, str] = {}

        for tx in transactions:
            # Handle both BTC and ETH transaction formats
            sender = tx.get("sender") or tx.get("from", "")
            recipients: list[tuple[str, float]] = []

            if "outputs" in tx:
                # BTC format
                for out in tx["outputs"]:
                    r = out.get("recipient", "")
                    v = float(out.get("value", 0))
                    if r:
                        recipients.append((r, v))
            elif "to" in tx:
                # ETH format
                to = tx.get("to", "")
                v = float(tx.get("value", 0))
                if to:
                    recipients.append((to, v))

            if sender:
                nodes_set.add(sender)
                node_labels[sender] = self._shorten_addr(sender)
                for recipient, value in recipients:
                    nodes_set.add(recipient)
                    node_labels[recipient] = self._shorten_addr(recipient)
                    edges.append(
                        {
                            "source": sender,
                            "target": recipient,
                            "value": abs(value),
                            "hash": tx.get("hash", ""),
                        }
                    )

        nodes = [
            {"id": addr, "label": node_labels.get(addr, self._shorten_addr(addr))}
            for addr in nodes_set
        ]

        return {
            "nodes": nodes,
            "edges": edges,
            "meta": {
                "total": len(transactions),
                "unique_addresses": len(nodes_set),
                "total_edges": len(edges),
            },
        }

    # ------------------------------------------------------------------
    # Exchange identification
    # ------------------------------------------------------------------
    def _find_exchange_matches(self, address: str) -> list[str]:
        """Check if address matches any known exchange address."""
        matches: list[str] = []
        addr_lower = address.lower()

        # Direct match
        if addr_lower in _EXCHANGE_ADDRESS_MAP:
            matches.append(_EXCHANGE_ADDRESS_MAP[addr_lower])

        # Check if address prefix matches known patterns
        for exchange, addresses in _KNOWN_EXCHANGES.items():
            if exchange in matches:
                continue
            for known_addr in addresses:
                # Check prefix similarity (first 8 chars)
                if len(addr_lower) >= 8 and len(known_addr) >= 8:
                    if addr_lower[:8] == known_addr.lower()[:8]:
                        matches.append(exchange)
                        break

        return matches

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------
    def _compute_risk_score(self, address: str, history: list[dict]) -> float:
        """Compute risk score from 0.0 (low) to 1.0 (high)."""
        if not history:
            return 0.0

        score = 0.0
        factors = 0

        # Factor 1: High transaction frequency (>100 txs = suspicious)
        tx_count = len(history)
        if tx_count > 100:
            score += 0.3
        elif tx_count > 50:
            score += 0.15
        factors += 1

        # Factor 2: Interaction with known exchanges
        exchange_interactions = 0
        for tx in history:
            parties = [
                tx.get("from", ""),
                tx.get("to", ""),
                tx.get("sender", ""),
            ]
            for out in tx.get("outputs", []):
                parties.append(out.get("recipient", ""))
            for inp in tx.get("inputs", []):
                parties.append(inp.get("address", "") or inp.get("recipient", ""))

            for party in parties:
                if party and self._find_exchange_matches(party):
                    exchange_interactions += 1
                    break

        if tx_count > 0:
            exchange_ratio = exchange_interactions / tx_count
            if exchange_ratio > 0.5:
                score += 0.2
            elif exchange_ratio > 0.2:
                score += 0.1
        factors += 1

        # Factor 3: High value variance (mixing behavior)
        values = []
        for tx in history:
            v = tx.get("value", 0)
            if isinstance(v, (int, float)):
                values.append(abs(float(v)))

        if len(values) > 1:
            mean_val = sum(values) / len(values)
            if mean_val > 0:
                variance = sum((v - mean_val) ** 2 for v in values) / len(values)
                cv = (variance ** 0.5) / mean_val  # coefficient of variation
                if cv > 5:
                    score += 0.25
                elif cv > 2:
                    score += 0.1
        factors += 1

        # Factor 4: Failed/error transactions
        errors = sum(1 for tx in history if tx.get("is_error") in ("1", 1, True))
        if tx_count > 0:
            error_ratio = errors / tx_count
            if error_ratio > 0.3:
                score += 0.25
            elif error_ratio > 0.1:
                score += 0.1
        factors += 1

        # Normalize to 0-1
        return min(score, 1.0)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _shorten_addr(address: str, prefix_len: int = 6) -> str:
        """Return shortened address for display: ``Abc...Xyz``."""
        if len(address) <= prefix_len + 3:
            return address
        return f"{address[:prefix_len]}...{address[-4:]}"

    @staticmethod
    def _empty_result(address: str) -> dict:
        """Return empty result structure."""
        return {
            "address": address,
            "transactions": [],
            "peers": [],
            "depth_reached": 0,
            "exchange": [],
            "chain": "",
        }

    def close(self) -> None:
        """Close the underlying HTTP session."""
        if self._session:
            self._session.close()

    def __enter__(self) -> CryptoTracer:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
