"""Temporal Analysis for ARGUS.

Timeline construction, anomaly detection (z-score), event correlation,
and activity forecasting for onions/marketplaces.

All optional dependencies are imported via try/except — the analyzer
works with stdlib-only if scipy/prophet/plotly are not installed.
"""

from __future__ import annotations

import logging
import math
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone, timezone
from typing import Any

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependencies — graceful fallback
# ---------------------------------------------------------------------------
try:
    from scipy.stats import zscore  # type: ignore[import-untyped]

    _HAS_SCIPY = True
except ImportError:
    _HAS_SCIPY = False
    _logger.debug("scipy not installed — using manual z-score computation")

try:
    from prophet import Prophet  # type: ignore[import-untyped]

    _HAS_PROPHET = True
except ImportError:
    _HAS_PROPHET = False
    _logger.debug("prophet not installed — using moving-average forecast fallback")

try:
    import plotly.graph_objects as go  # type: ignore[import-untyped]

    _HAS_PLOTLY = True
except ImportError:
    _HAS_PLOTLY = False
    _logger.debug("plotly not installed — to_plotly_timeline returns raw dict only")


# ---------------------------------------------------------------------------
# TemporalAnalyzer
# ---------------------------------------------------------------------------


class TemporalAnalyzer:
    """Timeline, anomaly detection, correlation, and forecast for events.

    Designed for dark-web marketplace activity analysis (e.g. a marketplace
    consistently coming online at 03:00 UTC).

    Usage::

        analyzer = TemporalAnalyzer()
        analyzer.add_event(datetime.now(timezone.utc), "marketplace_online", {"onion": "..."})
        timeline = analyzer.get_timeline()
        anomalies = analyzer.detect_anomalies()
        forecast = analyzer.forecast_activity(periods=7)
    """

    def __init__(self, z_threshold: float = 2.0) -> None:
        """Initialize the analyzer.

        Args:
            z_threshold: Absolute z-score above which a point is considered
                an anomaly. Default 2.0 (~95% confidence for normal data).
        """
        self._events: list[dict[str, Any]] = []
        self._z_threshold = z_threshold

    # -- event ingestion -----------------------------------------------------

    def add_event(self, timestamp: datetime, event_type: str, data: dict[str, Any]) -> None:
        """Record a temporal event.

        Args:
            timestamp: When the event occurred.
            event_type: Category label (e.g. ``"marketplace_online"``).
            data: Arbitrary payload associated with the event.
        """
        self._events.append(
            {
                "timestamp": timestamp,
                "event_type": event_type,
                "data": data,
            }
        )
        # Keep sorted for deterministic timeline output
        self._events.sort(key=lambda e: e["timestamp"])

    # -- timeline ------------------------------------------------------------

    def get_timeline(self) -> list[dict[str, Any]]:
        """Return the chronological timeline of all recorded events.

        Returns:
            List of event dicts sorted by timestamp (oldest first).
        """
        return list(self._events)

    # -- anomaly detection ---------------------------------------------------

    def detect_anomalies(self) -> list[dict[str, Any]]:
        """Detect anomalous events using z-score on hourly event counts.

        Groups events into hourly bins per event_type, computes the z-score
        of each bin's count, and returns bins whose absolute z-score exceeds
        ``z_threshold``.

        Returns:
            List of anomaly dicts with keys: ``event_type``, ``hour``,
            ``count``, ``z_score``. Empty if fewer than 3 data points.
        """
        if not self._events:
            return []

        # Bin events per (event_type, hour)
        hourly_counts: dict[str, dict[datetime, int]] = defaultdict(lambda: defaultdict(int))
        for ev in self._events:
            hour_key = ev["timestamp"].replace(minute=0, second=0, microsecond=0)
            hourly_counts[ev["event_type"]][hour_key] += 1

        anomalies: list[dict[str, Any]] = []

        for event_type, hour_map in hourly_counts.items():
            counts = list(hour_map.values())
            if len(counts) < 3:
                continue

            z_scores = self._compute_z_scores(counts)

            for (hour, count), z in zip(hour_map.items(), z_scores):
                if abs(z) >= self._z_threshold:
                    anomalies.append(
                        {
                            "event_type": event_type,
                            "hour": hour,
                            "count": count,
                            "z_score": round(z, 4),
                        }
                    )

        anomalies.sort(key=lambda a: abs(a["z_score"]), reverse=True)
        return anomalies

    @staticmethod
    def _compute_z_scores(values: list[int | float]) -> list[float]:
        """Compute z-scores for a list of numeric values.

        Uses ``scipy.stats.zscore`` when available; falls back to a manual
        computation using mean and sample standard deviation.
        """
        if _HAS_SCIPY:
            return list(zscore(values))

        # Manual fallback
        if len(values) < 2:
            return [0.0] * len(values)

        mean = statistics.mean(values)
        stdev = statistics.stdev(values)
        if stdev == 0:
            return [0.0] * len(values)

        return [(v - mean) / stdev for v in values]

    # -- correlation ---------------------------------------------------------

    def correlate_events(self, event_a: str, event_b: str) -> float:
        """Compute temporal correlation between two event types.

        Builds hourly count series for each event type over the shared time
        range, then computes Pearson correlation. Returns 0.0 when there are
        fewer than 3 overlapping bins.

        Args:
            event_a: First event type label.
            event_b: Second event type label.

        Returns:
            Pearson correlation coefficient in [-1.0, 1.0].
        """
        # Build hourly series for each type
        series_a: dict[datetime, int] = defaultdict(int)
        series_b: dict[datetime, int] = defaultdict(int)

        for ev in self._events:
            hour_key = ev["timestamp"].replace(minute=0, second=0, microsecond=0)
            if ev["event_type"] == event_a:
                series_a[hour_key] += 1
            elif ev["event_type"] == event_b:
                series_b[hour_key] += 1

        # Union of hours
        all_hours = sorted(set(series_a) | set(series_b))
        if len(all_hours) < 3:
            return 0.0

        vec_a = [series_a.get(h, 0) for h in all_hours]
        vec_b = [series_b.get(h, 0) for h in all_hours]

        return self._pearson(vec_a, vec_b)

    @staticmethod
    def _pearson(x: list[float], y: list[float]) -> float:
        """Pearson correlation coefficient between two equal-length vectors."""
        n = len(x)
        if n < 2:
            return 0.0

        mean_x = sum(x) / n
        mean_y = sum(y) / n

        num = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y))
        den_x = math.sqrt(sum((xi - mean_x) ** 2 for xi in x))
        den_y = math.sqrt(sum((yi - mean_y) ** 2 for yi in y))

        if den_x == 0 or den_y == 0:
            return 0.0

        return num / (den_x * den_y)

    # -- forecasting ---------------------------------------------------------

    def forecast_activity(self, periods: int = 7) -> list[dict[str, Any]]:
        """Forecast future activity for each event type.

        Uses Prophet when available; otherwise falls back to simple moving
        average over the last ``periods`` observed bins.

        Args:
            periods: Number of future hourly bins to forecast.

        Returns:
            List of forecast dicts with keys: ``event_type``, ``timestamp``,
            ``predicted_count``. Empty if no events recorded.
        """
        if not self._events:
            return []

        if _HAS_PROPHET:
            return self._forecast_prophet(periods)
        return self._forecast_moving_average(periods)

    def _forecast_prophet(self, periods: int) -> list[dict[str, Any]]:
        """Forecast using Facebook Prophet."""
        # Aggregate to hourly counts per event_type
        hourly_by_type: dict[str, dict[datetime, int]] = defaultdict(lambda: defaultdict(int))
        for ev in self._events:
            hour_key = ev["timestamp"].replace(minute=0, second=0, microsecond=0)
            hourly_by_type[ev["event_type"]][hour_key] += 1

        forecasts: list[dict[str, Any]] = []

        for event_type, hour_map in hourly_by_type.items():
            if len(hour_map) < 3:
                continue

            df_data = sorted(hour_map.items(), key=lambda kv: kv[0])
            try:
                import pandas as pd

                df = pd.DataFrame(df_data, columns=["ds", "y"])
                model = Prophet(daily_seasonality=True, weekly_seasonality=True)
                model.fit(df)

                future = model.make_future_dataframe(periods=periods, freq="h")
                forecast = model.predict(future)

                # Only return future rows
                last_known = max(hour_map)
                future_rows = forecast[forecast["ds"] > last_known]

                for _, row in future_rows.iterrows():
                    forecasts.append(
                        {
                            "event_type": event_type,
                            "timestamp": row["ds"].to_pydatetime(),
                            "predicted_count": max(0.0, float(row["yhat"])),
                        }
                    )
            except Exception as e:
                _logger.warning("Prophet forecast failed for %s: %s", event_type, e)
                # Fallback to moving average for this type
                ma = self._moving_average_forecast(hour_map, periods)
                for ts, val in ma:
                    forecasts.append(
                        {
                            "event_type": event_type,
                            "timestamp": ts,
                            "predicted_count": val,
                        }
                    )

        return forecasts

    def _forecast_moving_average(self, periods: int) -> list[dict[str, Any]]:
        """Forecast using simple moving average fallback."""
        hourly_by_type: dict[str, dict[datetime, int]] = defaultdict(lambda: defaultdict(int))
        for ev in self._events:
            hour_key = ev["timestamp"].replace(minute=0, second=0, microsecond=0)
            hourly_by_type[ev["event_type"]][hour_key] += 1

        forecasts: list[dict[str, Any]] = []
        for event_type, hour_map in hourly_by_type.items():
            if not hour_map:
                continue
            for ts, val in self._moving_average_forecast(hour_map, periods):
                forecasts.append(
                    {
                        "event_type": event_type,
                        "timestamp": ts,
                        "predicted_count": val,
                    }
                )

        return forecasts

    @staticmethod
    def _moving_average_forecast(
        hour_map: dict[datetime, int], periods: int
    ) -> list[tuple[datetime, float]]:
        """Simple moving average forecast from the last N observed hours."""
        if not hour_map:
            return []

        sorted_hours = sorted(hour_map)
        last_hour = sorted_hours[-1]
        counts = [hour_map[h] for h in sorted_hours]

        # Use last min(periods, len) values as the window
        window = counts[-periods:]
        avg = sum(window) / len(window) if window else 0.0

        result: list[tuple[datetime, float]] = []
        for i in range(1, periods + 1):
            result.append((last_hour + timedelta(hours=i), round(avg, 2)))

        return result

    # -- visualization -------------------------------------------------------

    def to_plotly_timeline(self) -> dict[str, Any]:
        """Build timeline data suitable for Plotly visualization.

        Returns a dict with ``data`` (list of trace dicts) and ``layout``.
        If plotly is installed, also attaches ``fig`` with a ``go.Figure``.

        Returns:
            Dict with keys ``data``, ``layout``, and optionally ``fig``.
        """
        # Group events by type for separate traces
        by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for ev in self._events:
            by_type[ev["event_type"]].append(ev)

        traces: list[dict[str, Any]] = []
        for event_type, events in by_type.items():
            timestamps = [ev["timestamp"] for ev in events]
            y_vals = [event_type] * len(timestamps)
            texts = [str(ev.get("data", "")) for ev in events]

            traces.append(
                {
                    "type": "scatter",
                    "mode": "markers",
                    "name": event_type,
                    "x": timestamps,
                    "y": y_vals,
                    "text": texts,
                    "marker": {"size": 10},
                }
            )

        result: dict[str, Any] = {
            "data": traces,
            "layout": {
                "title": "Temporal Activity Timeline",
                "xaxis": {"title": "Time"},
                "yaxis": {"title": "Event Type"},
                "hovermode": "closest",
            },
        }

        if _HAS_PLOTLY:
            result["fig"] = go.Figure(data=traces, layout=result["layout"])

        return result

    # -- stats ---------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics about recorded events.

        Returns:
            Dict with ``total_events``, ``event_types``, ``time_range``,
            ``events_per_type``.
        """
        if not self._events:
            return {
                "total_events": 0,
                "event_types": [],
                "time_range": None,
                "events_per_type": {},
            }

        timestamps = [ev["timestamp"] for ev in self._events]
        per_type: dict[str, int] = defaultdict(int)
        for ev in self._events:
            per_type[ev["event_type"]] += 1

        return {
            "total_events": len(self._events),
            "event_types": sorted(set(per_type)),
            "time_range": {
                "start": min(timestamps),
                "end": max(timestamps),
            },
            "events_per_type": dict(per_type),
        }
