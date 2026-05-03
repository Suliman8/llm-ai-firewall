"""Pydantic request/response models for the gateway."""
from typing import Literal

from pydantic import BaseModel, Field

BackendName = Literal["mock", "openai", "anthropic"]
Verdict = Literal["pass", "uncertain", "block"]


class ChatRequest(BaseModel):
    backend: BackendName = Field(default="mock", description="Which LLM backend to use.")
    prompt: str = Field(..., min_length=1, max_length=20000, description="User prompt.")
    model: str | None = Field(default=None, description="Optional model override.")
    max_tokens: int = Field(default=512, ge=1, le=4096)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)


class FirewallVerdict(BaseModel):
    l1_score: float
    verdict: Verdict


class ChatResponse(BaseModel):
    backend: BackendName
    model: str
    reply: str
    usage: dict | None = None
    firewall: FirewallVerdict | None = None


class L1Status(BaseModel):
    loaded: bool
    f1: float | None = None
    block_threshold: float | None = None
    pass_threshold: float | None = None


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    backends_available: list[BackendName]
    l1: L1Status
