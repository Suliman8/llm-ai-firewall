"""OWASP LLM04 — Model DoS.

Real rate-limiting comes in W7. For W6 we cover the *resource-exhaustion*
sub-cases that the gateway can already enforce today: oversize prompts
and oversize scan payloads must be rejected before any model is called.
"""
from __future__ import annotations


async def test_llm04_oversize_prompt_rejected_at_validation(client):
    """Pydantic enforces max_length=20000 on ChatRequest.prompt → 422."""
    huge = "A" * 20001
    resp = await client.post(
        "/v1/chat",
        json={"backend": "mock", "prompt": huge},
    )
    assert resp.status_code == 422, resp.text
    body = resp.json()
    assert any("prompt" in (e.get("loc") or []) for e in body.get("detail", [])), body


async def test_llm04_empty_prompt_rejected(client):
    resp = await client.post(
        "/v1/chat",
        json={"backend": "mock", "prompt": ""},
    )
    assert resp.status_code == 422, resp.text


async def test_llm04_scan_oversize_pdf_rejected(client):
    """src/scanner/extractor.py caps decoded PDF at 10 MB."""
    import base64
    payload = base64.b64encode(b"%PDF-1.0\n" + b"A" * 11_000_000).decode()
    resp = await client.post(
        "/v1/scan",
        json={"source": "pdf", "pdf_b64": payload},
    )
    assert resp.status_code == 422, resp.text
    assert "too large" in resp.text.lower() or "extraction failed" in resp.text.lower()


async def test_llm04_scan_private_url_rejected(client):
    """SSRF defence — private/loopback hosts must be refused."""
    resp = await client.post(
        "/v1/scan",
        json={"source": "url", "url": "http://127.0.0.1:8000/health"},
    )
    assert resp.status_code == 422, resp.text
    assert "ssrf" in resp.text.lower() or "private" in resp.text.lower()
