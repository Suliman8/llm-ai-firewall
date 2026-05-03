"""Anthropic backend adapter — uses the official `anthropic` SDK."""
from anthropic import AsyncAnthropic

from src.backends.base import Backend
from src.gateway.config import settings
from src.gateway.schemas import ChatRequest, ChatResponse


class AnthropicBackend(Backend):
    name = "anthropic"
    default_model = "claude-haiku-4-5-20251001"

    def __init__(self) -> None:
        self.client = (
            AsyncAnthropic(api_key=settings.anthropic_api_key) if self.is_available() else None
        )

    def is_available(self) -> bool:
        key = settings.anthropic_api_key
        return bool(key) and not key.startswith("sk-ant-replace")

    async def chat(self, request: ChatRequest) -> ChatResponse:
        model = request.model or self.default_model
        message = await self.client.messages.create(
            model=model,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            messages=[{"role": "user", "content": request.prompt}],
        )
        text = "".join(b.text for b in message.content if hasattr(b, "text"))
        return ChatResponse(
            backend="anthropic",
            model=model,
            reply=text,
            usage={
                "input_tokens": message.usage.input_tokens,
                "output_tokens": message.usage.output_tokens,
            },
        )
