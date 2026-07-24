"""Baseline tracker — rolling average (industry standard Prometheus/Grafana approach).

Maintains a sliding window of the last N metric snapshots per session.
Baseline for a metric = median of the last N observations.
This is exactly how Grafana alerting baselines work.
"""
from collections import deque, defaultdict
from statistics import median
from typing import Optional
import config


class BaselineTracker:
    """Tracks rolling baselines for key metrics across all sessions."""

    def __init__(self, window: int = config.BASELINE_WINDOW):
        self._window = window
        # Per-metric sliding windows: metric_name -> deque of float values
        self._windows: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=self._window))

    def update(self, metrics: dict) -> None:
        """Feed a new metrics snapshot in. Call this whenever fresh metrics arrive."""
        mappings = {
            "dns_avg_ms":        metrics.get("dns", {}).get("avg_resolution_ms"),
            "dns_p95_ms":        metrics.get("dns", {}).get("p95_resolution_ms"),
            "tcp_rtt_p50_us":    metrics.get("tcp", {}).get("rtt_p50_us"),
            "tcp_rtt_p95_us":    metrics.get("tcp", {}).get("rtt_p95_us"),
            "tcp_retransmit_pct":metrics.get("tcp", {}).get("retransmission_rate_pct"),
            "http_p50_ms":       metrics.get("http", {}).get("latency_p50_ms"),
            "http_p95_ms":       metrics.get("http", {}).get("latency_p95_ms"),
            "http_error_pct":    metrics.get("http", {}).get("error_rate_pct"),
            "bps_in":            metrics.get("network", {}).get("bps_in"),
            "bps_out":           metrics.get("network", {}).get("bps_out"),
            "packets_per_sec":   metrics.get("network", {}).get("packets_per_sec"),
        }
        for key, val in mappings.items():
            if val is not None and isinstance(val, (int, float)) and val >= 0:
                self._windows[key].append(float(val))

    def baseline(self, metric: str) -> Optional[float]:
        """Return the median baseline for a metric, or None if not enough data."""
        w = self._windows.get(metric)
        if not w or len(w) < 3:
            return None
        return median(w)

    def annotate(self, metric: str, current: float, unit: str = "") -> str:
        """
        Returns the value string, with [ELEVATED] or [LOW] annotation if it
        deviates significantly from baseline. This is what makes AI responses precise.

        Example output:
          "410ms [ELEVATED — baseline 45ms, +811%]"
          "1.2% [NORMAL — baseline 1.1%]"
        """
        b = self.baseline(metric)
        val_str = f"{current:.1f}{unit}" if isinstance(current, float) else f"{current}{unit}"

        if b is None or b == 0:
            return val_str

        pct_change = ((current - b) / b) * 100

        # Thresholds: >50% above baseline → elevated; >100% → significantly elevated
        if pct_change > 100:
            return f"{val_str} [ELEVATED — baseline {b:.1f}{unit}, +{pct_change:.0f}%]"
        elif pct_change > 50:
            return f"{val_str} [ABOVE BASELINE — baseline {b:.1f}{unit}, +{pct_change:.0f}%]"
        elif pct_change < -50:
            return f"{val_str} [BELOW BASELINE — baseline {b:.1f}{unit}, {pct_change:.0f}%]"
        else:
            return val_str


# Module-level singleton — shared across the whole service process
tracker = BaselineTracker()
