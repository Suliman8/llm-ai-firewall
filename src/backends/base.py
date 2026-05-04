"""Abstract base class every LLM backend must implement.

Forcing a common interface means the gateway code doesn't care whether the
backend is OpenAI, Anthropic, or a self-hosted Llama — it just calls `.chat()`.
"""
from abc import ABC, abstractmethod

from src.gateway.schemas import ChatRequest, ChatResponse


class Backend(ABC):
    name: str

    @abstractmethod
    async def chat(self, request: ChatRequest, system_prompt: str = "") -> ChatResponse:
        """Forward the prompt to the underlying LLM and return a response.

        system_prompt: gateway-built system prompt (with canary already injected).
        Empty string means "no system message".
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Whether this backend is configured (has API key, etc.)."""
