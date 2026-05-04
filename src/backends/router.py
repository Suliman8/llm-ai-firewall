"""Backend router — picks the right backend instance based on the request.

Returns 400 for unknown backends, 503 for backends that aren't configured.
"""
from fastapi import HTTPException

from src.backends.anthropic_backend import AnthropicBackend
from src.backends.base import Backend
from src.backends.mock_backend import MockBackend
from src.backends.ollama_backend import OllamaBackend
from src.backends.openai_backend import OpenAIBackend
from src.gateway.schemas import BackendName


class BackendRouter:
    def __init__(self) -> None:
        self._backends: dict[BackendName, Backend] = {
            "mock": MockBackend(),
            "openai": OpenAIBackend(),
            "anthropic": AnthropicBackend(),
            "ollama": OllamaBackend(),
        }

    def get(self, name: BackendName) -> Backend:
        backend = self._backends.get(name)
        if backend is None:
            raise HTTPException(status_code=400, detail=f"Unknown backend: {name}")
        if not backend.is_available():
            raise HTTPException(
                status_code=503,
                detail=(
                    f"Backend '{name}' is not configured. "
                    f"Add the matching API key to .env or use backend='mock'."
                ),
            )
        return backend

    def available(self) -> list[BackendName]:
        return [n for n, b in self._backends.items() if b.is_available()]


router = BackendRouter()
