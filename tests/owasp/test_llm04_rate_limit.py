"""OWASP LLM04 — Model DoS, runtime layer.

Unit tests on the in-memory token-bucket. These don't drive the FastAPI
client because the OWASP test suite shares one API key across ~38 calls,
and exhausting the bucket here would flake other tests in the session.

The end-to-end proof of rate-limiting was done manually (see W7.md test
log). These tests lock down the bucket-math so future commits can't
regress the algorithm.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from src.firewall.rate_limit import InMemoryTokenBucket


async def test_rate_limit_first_request_allowed_with_full_bucket():
    bucket = InMemoryTokenBucket(capacity=10, refill_per_sec=1.0)
    v = await bucket.check("alice")
    assert v.allowed is True
    assert v.remaining == pytest.approx(9.0, abs=1e-3)


async def test_rate_limit_capacity_hit_returns_429_signal():
    """Exhaust the bucket; the next request must be denied."""
    bucket = InMemoryTokenBucket(capacity=5, refill_per_sec=0.0)  # no refill
    for _ in range(5):
        v = await bucket.check("bob")
        assert v.allowed is True
    # 6th request → bucket empty
    v = await bucket.check("bob")
    assert v.allowed is False
    assert v.remaining < 1.0


async def test_rate_limit_per_key_isolation():
    """Different API keys must have independent buckets."""
    bucket = InMemoryTokenBucket(capacity=2, refill_per_sec=0.0)
    # alice uses both her tokens
    assert (await bucket.check("alice")).allowed is True
    assert (await bucket.check("alice")).allowed is True
    assert (await bucket.check("alice")).allowed is False
    # bob still has full bucket
    assert (await bucket.check("bob")).allowed is True
    assert (await bucket.check("bob")).allowed is True
    assert (await bucket.check("bob")).allowed is False


async def test_rate_limit_refills_over_time():
    """After waiting refill_period seconds, a new token should be available."""
    bucket = InMemoryTokenBucket(capacity=2, refill_per_sec=10.0)  # 10/sec → 100ms per token
    # Drain
    await bucket.check("carol")
    await bucket.check("carol")
    drained = await bucket.check("carol")
    assert drained.allowed is False
    # Wait long enough for at least one refill
    await asyncio.sleep(0.15)
    refilled = await bucket.check("carol")
    assert refilled.allowed is True


async def test_rate_limit_retry_after_is_positive_when_denied():
    bucket = InMemoryTokenBucket(capacity=1, refill_per_sec=2.0)
    await bucket.check("dave")  # consume the only token
    v = await bucket.check("dave")
    assert v.allowed is False
    assert v.retry_after_sec > 0
    # 2 tokens/sec → next token in ≤ 0.5 s
    assert v.retry_after_sec < 1.0
