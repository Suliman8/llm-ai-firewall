"""Pydantic request/response models for the gateway."""
from typing import Literal

from pydantic import BaseModel, Field

BackendName = Literal["mock", "openai", "anthropic"]
Verdict = Literal["pass", "uncertain", "block"]


# ───────── Request ─────────

class ChatRequest(BaseModel):
    backend: BackendName = Field(default="mock", description="Which LLM backend to use.")
    prompt: str = Field(..., min_length=1, max_length=20000, description="User prompt.")
    model: str | None = Field(default=None, description="Optional model override.")
    max_tokens: int = Field(default=512, ge=1, le=4096)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)


# ───────── Per-layer firewall results ─────────

class L1aResult(BaseModel):
    score: float
    verdict: Verdict


class L1bResult(BaseModel):
    score: float
    verdict: Verdict


class L2Result(BaseModel):
    verdict: Literal["pass", "block"]
    confidence: float
    reason: str


class FirewallVerdict(BaseModel):
    overall: Literal["pass", "block"]
    blocked_by: Literal["L1a", "L1b", "L2"] | None = None
    l1a: L1aResult
    l1b: L1bResult | None = None
    l2: L2Result | None = None


# ───────── Response ─────────

class ChatResponse(BaseModel):
    backend: BackendName
    model: str
    reply: str
    usage: dict | None = None
    firewall: FirewallVerdict | None = None


# ───────── Health ─────────

class L1aStatus(BaseModel):
    loaded: bool
    f1: float | None = None
    block_threshold: float | None = None
    pass_threshold: float | None = None


class L1bStatus(BaseModel):
    loaded: bool


class L2Status(BaseModel):
    loaded: bool
    model: str | None = None


class FirewallStatus(BaseModel):
    l1a: L1aStatus
    l1b: L1bStatus
    l2: L2Status


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    backends_available: list[BackendName]
    firewall: FirewallStatus
