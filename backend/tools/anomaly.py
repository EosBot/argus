"""AnomalyDetection — z-score based anomaly detection for scan results.

Detects anomalies in investigation findings using statistical methods
(z-score, IQR) and configurable thresholds.

Usage::

    from backend.tools.anomaly import AnomalyDetection

    detector = AnomalyDetection()
    result = await detector.detect([10, 12, 11, 13, 100, 11, 12])
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AnomalyResult:
    """Result of anomaly detection.

    Attributes:
        anomalies: List of detected anomaly dicts.
        total_values: Total number of values analyzed.
        anomaly_count: Number of anomalies detected.
        anomaly_rate: Ratio of anomalies to total values.
        threshold_used: Z-score threshold used.
        statistics: Summary statistics (mean, std, min, max).
        is_anomalous: Whether the dataset contains anomalies.
    """

    anomalies: list[dict[str, Any]] = field(default_factory=list)
    total_values: int = 0
    anomaly_count: int = 0
    anomaly_rate: float = 0.0
    threshold_used: float = 2.0
    statistics: dict[str, float] = field(default_factory=dict)
    is_anomalous: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "anomalies": self.anomalies,
            "total_values": self.total_values,
            "anomaly_count": self.anomaly_count,
            "anomaly_rate": self.anomaly_rate,
            "threshold_used": self.threshold_used,
            "statistics": self.statistics,
            "is_anomalous": self.is_anomalous,
        }


class AnomalyDetection:
    """Detect anomalies in investigation data using statistical methods.

    Supports:
    - Z-score based detection for numerical data
    - IQR (Interquartile Range) method
    - Threshold-based detection for scan results
    - Configurable sensitivity
    """

    def __init__(
        self,
        z_threshold: float = 2.0,
        iqr_multiplier: float = 1.5,
        min_samples: int = 5,
    ) -> None:
        """Initialize anomaly detector.

        Args:
            z_threshold: Z-score threshold (default: 2.0 = ~95% confidence).
            iqr_multiplier: IQR multiplier for outlier detection.
            min_samples: Minimum samples needed for statistical detection.
        """
        self._z_threshold = z_threshold
        self._iqr_multiplier = iqr_multiplier
        self._min_samples = min_samples

    async def detect(
        self,
        values: list[float],
        labels: list[str] | None = None,
        method: str = "zscore",
    ) -> AnomalyResult:
        """Detect anomalies in a list of numerical values.

        Args:
            values: List of numerical values to analyze.
            labels: Optional labels for each value.
            method: Detection method ("zscore", "iqr", or "both").

        Returns:
            AnomalyResult with detected anomalies and statistics.
        """
        if not values or len(values) < self._min_samples:
            return AnomalyResult(
                total_values=len(values),
                threshold_used=self._z_threshold,
                statistics=self._compute_stats(values) if values else {},
            )

        stats = self._compute_stats(values)
        anomalies: list[dict[str, Any]] = []

        if method in ("zscore", "both"):
            z_anomalies = self._detect_zscore(values, labels, stats)
            anomalies.extend(z_anomalies)

        if method in ("iqr", "both"):
            iqr_anomalies = self._detect_iqr(values, labels)
            # Merge with z-score anomalies (avoid duplicates)
            existing_indices = {a.get("index") for a in anomalies}
            for a in iqr_anomalies:
                if a.get("index") not in existing_indices:
                    anomalies.append(a)

        # Sort by index
        anomalies.sort(key=lambda a: a.get("index", 0))

        anomaly_count = len(anomalies)
        return AnomalyResult(
            anomalies=anomalies,
            total_values=len(values),
            anomaly_count=anomaly_count,
            anomaly_rate=round(anomaly_count / len(values), 4),
            threshold_used=self._z_threshold,
            statistics=stats,
            is_anomalous=anomaly_count > 0,
        )

    async def detect_in_findings(
        self,
        findings: list[dict[str, Any]],
        value_key: str = "score",
        threshold: float | None = None,
    ) -> AnomalyResult:
        """Detect anomalies in investigation findings.

        Args:
            findings: List of finding dicts (each containing value_key).
            value_key: Key to extract numerical value from each finding.
            threshold: Optional override for z-score threshold.

        Returns:
            AnomalyResult with detected anomalies.
        """
        if not findings:
            return AnomalyResult()

        values: list[float] = []
        valid_indices: list[int] = []

        for i, finding in enumerate(findings):
            val = finding.get(value_key)
            if isinstance(val, (int, float)):
                values.append(float(val))
                valid_indices.append(i)

        if len(values) < self._min_samples:
            return AnomalyResult(
                total_values=len(values),
                threshold_used=threshold or self._z_threshold,
            )

        old_threshold = self._z_threshold
        if threshold is not None:
            self._z_threshold = threshold

        labels = [findings[i].get("name", f"finding_{i}") for i in valid_indices]
        result = await self.detect(values, labels=labels)

        # Map back to original indices
        for anomaly in result.anomalies:
            idx = anomaly.get("index", 0)
            if idx < len(valid_indices):
                original_idx = valid_indices[idx]
                anomaly["finding"] = findings[original_idx]
                anomaly["original_index"] = original_idx

        self._z_threshold = old_threshold
        return result

    async def detect_port_anomalies(
        self,
        scan_results: list[dict[str, Any]],
    ) -> AnomalyResult:
        """Detect anomalous ports in scan results.

        Flags ports that are unusual based on frequency analysis.

        Args:
            scan_results: List of scan result dicts with 'port' key.

        Returns:
            AnomalyResult for port distribution.
        """
        if not scan_results:
            return AnomalyResult()

        # Count port frequencies
        port_counts: dict[int, int] = {}
        ports: list[int] = []

        for result in scan_results:
            port = result.get("port")
            if isinstance(port, int):
                ports.append(port)

        if len(ports) < self._min_samples:
            return AnomalyResult(total_values=len(ports))

        # Use port numbers as values for z-score
        return await self.detect(
            [float(p) for p in ports],
            labels=[f"port_{p}" for p in ports],
        )

    def _detect_zscore(
        self,
        values: list[float],
        labels: list[str] | None,
        stats: dict[str, float],
    ) -> list[dict[str, Any]]:
        """Detect anomalies using z-score method."""
        mean = stats.get("mean", 0)
        std = stats.get("std", 0)

        if std == 0:
            return []

        anomalies: list[dict[str, Any]] = []
        for i, val in enumerate(values):
            z_score = (val - mean) / std
            if abs(z_score) > self._z_threshold:
                anomalies.append({
                    "index": i,
                    "value": val,
                    "label": labels[i] if labels and i < len(labels) else f"value_{i}",
                    "z_score": round(z_score, 4),
                    "direction": "high" if z_score > 0 else "low",
                    "severity": self._zscore_severity(abs(z_score)),
                    "method": "zscore",
                })

        return anomalies

    def _detect_iqr(
        self,
        values: list[float],
        labels: list[str] | None,
    ) -> list[dict[str, Any]]:
        """Detect anomalies using IQR method."""
        sorted_vals = sorted(values)
        n = len(sorted_vals)

        q1_idx = n // 4
        q3_idx = (3 * n) // 4
        q1 = sorted_vals[q1_idx]
        q3 = sorted_vals[q3_idx]
        iqr = q3 - q1

        if iqr == 0:
            return []

        lower_bound = q1 - self._iqr_multiplier * iqr
        upper_bound = q3 + self._iqr_multiplier * iqr

        anomalies: list[dict[str, Any]] = []
        for i, val in enumerate(values):
            if val < lower_bound or val > upper_bound:
                anomalies.append({
                    "index": i,
                    "value": val,
                    "label": labels[i] if labels and i < len(labels) else f"value_{i}",
                    "iqr_bounds": [round(lower_bound, 2), round(upper_bound, 2)],
                    "direction": "high" if val > upper_bound else "low",
                    "severity": "medium",
                    "method": "iqr",
                })

        return anomalies

    @staticmethod
    def _compute_stats(values: list[float]) -> dict[str, float]:
        """Compute summary statistics."""
        if not values:
            return {"mean": 0, "std": 0, "min": 0, "max": 0, "median": 0}

        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        std = math.sqrt(variance) if variance > 0 else 0

        sorted_vals = sorted(values)
        mid = n // 2
        median = sorted_vals[mid] if n % 2 == 1 else (sorted_vals[mid - 1] + sorted_vals[mid]) / 2

        return {
            "mean": round(mean, 4),
            "std": round(std, 4),
            "min": min(values),
            "max": max(values),
            "median": round(median, 4),
            "count": n,
        }

    @staticmethod
    def _zscore_severity(abs_z: float) -> str:
        """Classify severity based on absolute z-score."""
        if abs_z >= 3.5:
            return "critical"
        elif abs_z >= 3.0:
            return "high"
        elif abs_z >= 2.5:
            return "medium"
        return "low"
