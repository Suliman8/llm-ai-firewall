"""Mock backend — returns a canned reply. Always available, no API key needed.

Useful for: offline testing, CI, integration tests for the firewall layers
where we don't want to spend tokens.
"""
from src.backends.base import Backend
from src.gateway.schemas import ChatRequest, ChatResponse


class MockBackend(Backend):
    name = "mock"

    async def chat(self, request: ChatRequest) -> ChatResponse:
        reply = f"[MOCK reply] You said: {request.prompt[:200]}"
        return ChatResponse(
            backend="mock",
            model=request.model or "mock-1",
            reply=reply,
            usage={
                "prompt_tokens": len(request.prompt.split()),
                "completion_tokens": len(reply.split()),
            },
        )

    def is_available(self) -> bool:
        return True
