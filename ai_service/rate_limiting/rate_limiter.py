"""Rate limiter — per-session sliding window, in-memory."""
import time
from collections import defaultdict, deque
import config


class RateLimiter:
    def __init__(
        self,
        per_minute: int = config.RATE_LIMIT_PER_MINUTE,
        per_hour: int = config.RATE_LIMIT_PER_HOUR,
    ):
        self._per_minute = per_minute
        self._per_hour = per_hour
        # session_id → deque of timestamps (float)
        self._minute_windows: dict[str, deque] = defaultdict(lambda: deque())
        self._hour_windows: dict[str, deque] = defaultdict(lambda: deque())

    def _evict(self, dq: deque, cutoff: float):
        while dq and dq[0] < cutoff:
            dq.popleft()

    def check(self, session_id: str) -> tuple[bool, str]:
        """
        Returns (allowed: bool, reason: str).
        allowed=True means the request should proceed.
        """
        now = time.time()

        minute_dq = self._minute_windows[session_id]
        hour_dq   = self._hour_windows[session_id]

        self._evict(minute_dq, now - 60)
        self._evict(hour_dq, now - 3600)

        if len(minute_dq) >= self._per_minute:
            return False, "You've sent too many messages. Please wait a moment before asking another question."
        if len(hour_dq) >= self._per_hour:
            return False, "Hourly message limit reached. Please try again later."

        minute_dq.append(now)
        hour_dq.append(now)
        return True, ""


# Module-level singleton
limiter = RateLimiter()
