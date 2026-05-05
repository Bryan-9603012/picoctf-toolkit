# core/limiter.py
from __future__ import annotations

import threading
import time


class GlobalRateLimiter:
    """Thread-safe global QPS limiter (across all threads). qps<=0 => unlimited."""

    def __init__(self, qps: float):
        self.qps = float(qps)
        self._lock = threading.Lock()
        self._next_ts = 0.0

    def wait(self) -> None:
        if self.qps <= 0:
            return
        interval = 1.0 / self.qps
        with self._lock:
            now = time.time()
            if now < self._next_ts:
                time.sleep(self._next_ts - now)
                now = time.time()
            self._next_ts = now + interval