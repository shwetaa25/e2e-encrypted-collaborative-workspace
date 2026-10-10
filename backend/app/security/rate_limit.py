# app/security/rate_limit.py
# ─────────────────────────────────────────────────────────
# Tiny in-memory sliding-window limiter (per process).
# Used to slow down mass account creation from one client.
# For multi-replica production deployments, back this with Redis.
# ─────────────────────────────────────────────────────────

import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, max_hits: int, window_seconds: int) -> bool:
        """Records a hit and returns False when the key is over its budget."""
        if max_hits <= 0:
            return True
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] > window_seconds:
            q.popleft()
        if len(q) >= max_hits:
            return False
        q.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()


register_limiter = SlidingWindowLimiter()

lookup_limiter = SlidingWindowLimiter()   # per-user username lookups
search_limiter = SlidingWindowLimiter()   # per-user username search (suggestions)