"""OpenAI backend adapter — uses the official `openai` SDK."""
from openai import AsyncOpenAI

from src.backends.base import Backend
from src.gateway.config import settings
from src.gateway.schemas import ChatRequest, ChatResponse


class OpenAIBackend(Backend):
    name = "openai"
    default_model = "gpt-4o-mini"

    def __init__(self) -> None:
        self.client = (
            AsyncOpenAI(api_key=settings.openai_api_key) if self.is_available() else None
        )

    def is_available(self) -> bool:
        key = settings.openai_api_key
        return bool(key) and not key.startswith("sk-replace")

    async def chat(self, request: ChatRequest) -> ChatResponse:
        model = request.model or self.default_model
        completion = await self.client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": request.prompt}],
            max_tokens=request.max_tokens,
            temperature=request.temperature,
        )
        msg = completion.choices[0].message
        return ChatResponse(
            backend="openai",
            model=model,
            reply=msg.content or "",
            usage=completion.usage.model_dump() if completion.usage else None,
        )
