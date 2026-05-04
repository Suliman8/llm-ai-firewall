"""Ollama backend — talks to a local Ollama server (default port 11434).

Why this matters:
  - No external API, no key — fully self-hosted LLM
  - Data never leaves the machine (privacy / compliance)
  - Free; speed limited only by your CPU/GPU
  - Same Backend interface as the cloud providers — drop-in swap

Ollama exposes an OpenAI-compatible endpoint at /v1, so we re-use the
`openai` SDK pointed at http://localhost:11434/v1 with a dummy key.
"""
from __future__ import annotations

import logging

import httpx
from openai import AsyncOpenAI

from src.backends.base import Backend
from src.gateway.config import settings
from src.gateway.schemas import ChatRequest, ChatResponse

logger = logging.getLogger(__name__)


class OllamaBackend(Backend):
    name = "ollama"
    default_model = "llama3.2:3b"

    def __init__(self) -> None:
        # Ollama's OpenAI-compat endpoint is at /v1 under the base URL.
        base = settings.llama_base_url.rstrip("/") + "/v1"
        self.client = AsyncOpenAI(api_key="ollama-no-key", base_url=base)
        self._cached_available: bool | None = None

    def is_available(self) -> bool:
        """Cheap sync probe — checks if the Ollama daemon is reachable.

        Cached after first call so /health doesn't pay the HTTP cost on every hit.
        """
        if self._cached_available is not None:
            return self._cached_available
        try:
            r = httpx.get(settings.llama_base_url.rstrip("/") + "/api/tags", timeout=1.5)
            self._cached_available = r.status_code == 200
        except (httpx.HTTPError, OSError):
            self._cached_available = False
        return self._cached_available

    async def chat(self, request: ChatRequest, system_prompt: str = "") -> ChatResponse:
        model = request.model or self.default_model
        messages: list[dict] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": request.prompt})

        completion = await self.client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
        )
        msg = completion.choices[0].message
        return ChatResponse(
            backend="ollama",
            model=model,
            reply=msg.content or "",
            usage=completion.usage.model_dump() if completion.usage else None,
        )
