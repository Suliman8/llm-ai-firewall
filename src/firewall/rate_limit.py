"""Per-key token-bucket rate limiter.

Why token bucket?
  - Allows bursts up to `capacity`, then sustained `refill_rate` per second.
  - Smoother than fixed-window counters (no boundary spikes).
  - Industry standard (AWS, Stripe, Cloudflare).

Two implementations behind one interface:
  - RedisTokenBucket — multi-process, persistent across restarts (production)
  - InMemoryTokenBucket — single-process, no deps (dev / test fallback)

The factory `get_rate_limiter()` picks Redis if reachable, otherwise
falls back to in-memory and logs a warning. Same graceful-degrade
pattern we use for L2 LLM-judge.
"""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RateLimitVerdict:
    allowed: bool
    remaining: float            # tokens left after this request
    retry_after_sec: float      # 0 if allowed, else seconds until next token
    capacity: int
    refill_per_sec: float


class RateLimiter(ABC):
    """Async interface — Redis impl needs awaits, in-memory impl doesn't."""

    @abstractmethod
    async def check(self, key: str) -> RateLimitVerdict:
        """Consume one token if available. Returns the verdict."""


# ─────────── In-memory implementation ───────────

class InMemoryTokenBucket(RateLimiter):
    """Single-process bucket store. Resets on restart."""

    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self._buckets: dict[str, tuple[float, float]] = {}    # key → (tokens, last_refill_ts)
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> RateLimitVerdict:
        now = time.monotonic()
        async with self._lock:
            tokens, last = self._buckets.get(key, (float(self.capacity), now))
            elapsed = now - last
            tokens = min(self.capacity, tokens + elapsed * self.refill_per_sec)

            if tokens >= 1.0:
                tokens -= 1.0
                self._buckets[key] = (tokens, now)
                return RateLimitVerdict(
                    allowed=True, remaining=tokens, retry_after_sec=0.0,
                    capacity=self.capacity, refill_per_sec=self.refill_per_sec,
                )
            # not enough tokens
            self._buckets[key] = (tokens, now)
            if self.refill_per_sec > 0:
                retry = (1.0 - tokens) / self.refill_per_sec
            else:
                retry = float("inf")     # bucket can never refill
            return RateLimitVerdict(
                allowed=False, remaining=tokens, retry_after_sec=retry,
                capacity=self.capacity, refill_per_sec=self.refill_per_sec,
            )


# ─────────── Redis implementation ───────────

# Lua script for atomic check-and-consume on Redis. Atomicity is critical:
# without it, two concurrent requests could both see "1 token" and both pass.
_REDIS_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refill = tonumber(ARGV[3])

local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil then
  tokens = capacity
  ts = now
end

local elapsed = math.max(0, now - ts)
tokens = math.min(capacity, tokens + elapsed * refill)

local allowed
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  allowed = 0
end

redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, 3600)
return {allowed, tostring(tokens)}
"""


class RedisTokenBucket(RateLimiter):
    def __init__(self, redis_client, capacity: int, refill_per_sec: float) -> None:
        self._r = redis_client
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self._lua = self._r.register_script(_REDIS_LUA)

    async def check(self, key: str) -> RateLimitVerdict:
        full_key = f"ratelimit:{key}"
        now = time.time()
        try:
            allowed, tokens_str = await self._lua(
                keys=[full_key],
                args=[now, self.capacity, self.refill_per_sec],
            )
        except Exception as e:
            logger.warning("Redis rate-limit check failed, allowing request: %s", e)
            return RateLimitVerdict(
                allowed=True, remaining=self.capacity, retry_after_sec=0.0,
                capacity=self.capacity, refill_per_sec=self.refill_per_sec,
            )
        tokens = float(tokens_str)
        if allowed:
            retry = 0.0
        elif self.refill_per_sec > 0:
            retry = (1.0 - tokens) / self.refill_per_sec
        else:
            retry = float("inf")
        return RateLimitVerdict(
            allowed=bool(allowed), remaining=tokens, retry_after_sec=retry,
            capacity=self.capacity, refill_per_sec=self.refill_per_sec,
        )


# ─────────── Factory ───────────

async def build_rate_limiter(redis_url: str, capacity: int, refill_per_sec: float) -> RateLimiter:
    """Try Redis; fall back to in-memory with a warning."""
    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url(redis_url, decode_responses=True)
        await client.ping()
        logger.info("Rate limiter: Redis at %s (cap=%d, %.2f/s)", redis_url, capacity, refill_per_sec)
        return RedisTokenBucket(client, capacity, refill_per_sec)
    except Exception as e:
        logger.warning(
            "Rate limiter: Redis unavailable (%s) — falling back to in-memory", e
        )
        return InMemoryTokenBucket(capacity, refill_per_sec)
