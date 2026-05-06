from __future__ import annotations

import time
from collections import defaultdict, deque


class InMemoryRateLimiter:
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._store: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> tuple[bool, int]:
        now = time.time()
        bucket = self._store[key]
        while bucket and bucket[0] <= now - self.window_seconds:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - bucket[0])) if bucket else self.window_seconds
            return False, max(1, retry_after)
        bucket.append(now)
        return True, 0


scan_rate_limiter = InMemoryRateLimiter(max_requests=6, window_seconds=60)
auth_rate_limiter = InMemoryRateLimiter(max_requests=20, window_seconds=60)
