"""Pytest fixtures for the OWASP LLM Top-10 test harness.

We mount the FastAPI app *in-process* via httpx.ASGITransport so the tests
don't need a running uvicorn — no network, no port, just direct ASGI calls.

The session-scoped `client` fixture loads the firewall layers exactly once
(the lifespan handler runs inside LifespanManager) so 30+ tests share one
copy of the XGBoost + DeBERTa models. First test takes ~30s, the rest are
sub-second each.
"""
from __future__ import annotations

import os

import httpx
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager

from src.detectors import l2_llm_judge
from src.gateway.app import app

API_KEY = "dev-secret-key"


@pytest_asyncio.fixture(scope="session")
async def client() -> httpx.AsyncClient:
    """In-process async client with the firewall fully booted.

    `startup_timeout=60` is needed because L1a + L1b model loading +
    HuggingFace Hub re-validation can exceed asgi-lifespan's default 5s.
    """
    os.environ.setdefault("GATEWAY_API_KEY", API_KEY)
    async with LifespanManager(app, startup_timeout=60.0, shutdown_timeout=10.0):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
            headers={"X-API-Key": API_KEY},
            timeout=60.0,
        ) as c:
            yield c


@pytest.fixture(scope="session")
def l2_available() -> bool:
    """True if the L2 LLM-judge could be loaded (Groq key present)."""
    return l2_llm_judge.is_loaded()


# Helper assertions used across multiple test files

def assert_blocked_by_input(response: httpx.Response, layers: tuple[str, ...]) -> None:
    """Assert the request was blocked at one of the given input layers."""
    assert response.status_code == 403, (
        f"expected 403 input-block, got {response.status_code}: {response.text[:200]}"
    )
    detail = response.json()["detail"]
    assert detail["blocked_by"] in layers, (
        f"expected blocked_by ∈ {layers}, got '{detail['blocked_by']}': {detail}"
    )


def assert_blocked_at_output(response: httpx.Response) -> None:
    assert response.status_code == 403, (
        f"expected 403 output-block, got {response.status_code}: {response.text[:200]}"
    )
    detail = response.json()["detail"]
    assert detail["blocked_by"] == "output", detail


def assert_passed(response: httpx.Response) -> None:
    assert response.status_code == 200, (
        f"expected 200 pass, got {response.status_code}: {response.text[:200]}"
    )
    body = response.json()
    fw = body.get("firewall", {})
    assert fw.get("overall") == "pass", fw
