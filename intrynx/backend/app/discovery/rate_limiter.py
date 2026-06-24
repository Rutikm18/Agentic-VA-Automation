"""
RateLimiter — enforces PPS limits per CIDR and business-hour windows
from the engagement's rules_of_engagement JSONB config.

RoE config shape (subset):
{
  "max_pps": 50,               # packets per second (global cap)
  "per_cidr_pps": {            # optional per-CIDR override
    "10.10.10.0/24": 10
  },
  "business_hours_only": true,
  "allowed_days": [1,2,3,4,5], # 1=Mon … 7=Sun (ISO weekday)
  "window_start": "09:00",
  "window_end": "18:00",
  "timezone": "UTC"
}
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
from datetime import datetime, timezone
from typing import Any


class RateLimiter:
    DEFAULT_PPS = 100

    def __init__(self, roe: dict[str, Any] | None = None):
        self._roe = roe or {}
        self._global_pps: float = float(self._roe.get("max_pps", self.DEFAULT_PPS))
        self._per_cidr: dict[str, float] = {
            cidr: float(pps)
            for cidr, pps in self._roe.get("per_cidr_pps", {}).items()
        }
        # Token bucket state: {cidr_or_global: (tokens, last_refill_ts)}
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    # ── Public API ─────────────────────────────────────────────────────────────

    def is_within_window(self) -> bool:
        """True if current time is inside the allowed scan window."""
        if not self._roe.get("business_hours_only"):
            return True
        now = datetime.now(timezone.utc)
        allowed_days: list[int] = self._roe.get("allowed_days", list(range(1, 8)))
        if now.isoweekday() not in allowed_days:
            return False
        start_str: str = self._roe.get("window_start", "00:00")
        end_str: str = self._roe.get("window_end", "23:59")
        h_s, m_s = map(int, start_str.split(":"))
        h_e, m_e = map(int, end_str.split(":"))
        now_minutes = now.hour * 60 + now.minute
        start_minutes = h_s * 60 + m_s
        end_minutes = h_e * 60 + m_e
        return start_minutes <= now_minutes <= end_minutes

    async def acquire(self, target_ip: str) -> None:
        """
        Blocks until a token is available for the given target IP.
        Raises RuntimeError if outside allowed scan window.
        """
        if not self.is_within_window():
            raise RuntimeError(
                "Scan blocked: current time is outside the engagement's allowed window"
            )
        cidr_key = self._resolve_cidr(target_ip)
        pps = self._per_cidr.get(cidr_key, self._global_pps)
        await self._consume_token(cidr_key, pps)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _resolve_cidr(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
            for cidr in self._per_cidr:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return cidr
        except ValueError:
            pass
        return "__global__"

    async def _consume_token(self, key: str, pps: float) -> None:
        interval = 1.0 / max(pps, 0.001)
        async with self._lock:
            now = time.monotonic()
            tokens, last = self._buckets.get(key, (pps, now))
            elapsed = now - last
            tokens = min(pps, tokens + elapsed * pps)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                return
            # Not enough tokens — calculate sleep time
            sleep_for = (1.0 - tokens) / pps
        await asyncio.sleep(sleep_for)
        async with self._lock:
            self._buckets[key] = (0.0, time.monotonic())
