"""CryptoTracer agent — BTC/ETH cryptocurrency wallet tracing.

Wraps argus_engine/intel/crypto_tracer.py for blockchain transaction tracing.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from backend.agents.base import BaseAgent
from backend.core.config import settings

logger = logging.getLogger(__name__)


class CryptoTracerAgent(BaseAgent):
    """Cryptocurrency tracing agent.

    Traces BTC/ETH transactions, identifies exchanges, calculates
    risk scores, and visualizes transaction flows.
    """

    name = "crypto_tracer"
    description = "Cryptocurrency tracing — traces BTC/ETH wallets, identifies exchanges, calculates risk scores"
    capabilities = [
        "btc_tracing",
        "eth_tracing",
        "exchange_identification",
        "risk_scoring",
        "flow_visualization",
    ]

    async def run(self, task: dict[str, Any]) -> dict[str, Any]:
        """Execute crypto tracing.

        Task dict keys:
            - address (str): Wallet address to trace (required)
            - chain (str): "btc", "eth", or "auto" (default: auto)
            - depth (int): Tracing depth 1-5 (default: 2)
            - visualize (bool): Generate flow visualization data (default: false)

        Returns:
            dict with keys: address, chain, transactions, peers, exchange, risk, flow
        """
        start = time.monotonic()
        address = task.get("address", "")
        if not address:
            return self._error_result("Missing required 'address' parameter")

        chain = task.get("chain", "auto")
        depth = min(task.get("depth", 2), 5)
        visualize = task.get("visualize", False)

        result: dict[str, Any] = {
            "agent_name": self.name,
            "address": address,
            "chain": chain,
        }

        loop = asyncio.get_event_loop()

        # Step 1: Trace the wallet
        trace_data = await loop.run_in_executor(
            None, self._trace_wallet, address, chain, depth
        )
        result.update(trace_data)

        # Step 2: Visualize flow if requested
        if visualize and trace_data.get("transactions"):
            flow_data = await loop.run_in_executor(
                None, self._visualize_flow, trace_data["transactions"]
            )
            result["flow"] = flow_data

        elapsed = (time.monotonic() - start) * 1000
        result["execution_time_ms"] = round(elapsed, 2)
        result["status"] = trace_data.get("status", "completed")
        return result

    def _trace_wallet(self, address: str, chain: str, depth: int) -> dict[str, Any]:
        """Trace wallet via argus_engine/intel/crypto_tracer.py."""
        try:
            from argus_engine.intel.crypto_tracer import CryptoTracer

            tracer = CryptoTracer(proxy_url=settings.tor_proxy)

            # Auto-detect chain
            if chain == "auto":
                if address.startswith("0x") and len(address) == 42:
                    chain = "eth"
                else:
                    chain = "btc"

            if chain == "eth":
                trace = tracer.trace_eth(address, depth=depth)
            else:
                trace = tracer.trace_btc(address, depth=depth)

            # Calculate risk if we have transactions
            risk = 0.0
            if trace.get("transactions"):
                risk = tracer.calculate_risk(address, trace["transactions"])

            return {
                "status": "completed",
                "chain": chain,
                "transactions": trace.get("transactions", []),
                "peers": trace.get("peers", []),
                "depth_reached": trace.get("depth_reached", 0),
                "exchange": trace.get("exchange", []),
                "risk_score": round(risk, 4),
                "transaction_count": len(trace.get("transactions", [])),
                "peer_count": len(trace.get("peers", [])),
            }
        except ImportError:
            logger.warning("argus_engine.intel.crypto_tracer not available")
            return {"status": "degraded", "error": "CryptoTracer not available"}
        except Exception as exc:
            logger.exception("Crypto tracing failed")
            return {"status": "failed", "error": str(exc)}

    def _visualize_flow(self, transactions: list[dict]) -> dict[str, Any]:
        """Generate flow visualization data."""
        try:
            from argus_engine.intel.crypto_tracer import CryptoTracer

            tracer = CryptoTracer(proxy_url=settings.tor_proxy)
            return tracer.visualize_flow(transactions)
        except Exception as exc:
            logger.exception("Flow visualization failed")
            return {"error": str(exc)}

    def _error_result(self, message: str) -> dict[str, Any]:
        return {
            "agent_name": self.name,
            "status": "failed",
            "error": message,
        }
