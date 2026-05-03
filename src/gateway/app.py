"""FastAPI application — the AI Firewall gateway entry point.

Run with:
    uvicorn src.gateway.app:app --reload --host 0.0.0.0 --port 8000

Endpoints:
    GET  /health      -> liveness + which backends + L1 status
    GET  /docs        -> auto-generated Swagger UI
    POST /v1/chat     -> proxy a prompt through L1 → backend (X-API-Key required)
"""
import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from src.backends.router import router as backend_router
from src.detectors import l1_classifier
from src.detectors.l1_classifier import L1Classifier
from src.gateway.config import settings
from src.gateway.schemas import (
    ChatRequest,
    ChatResponse,
    FirewallVerdict,
    HealthResponse,
    L1Status,
)

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("gateway")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the L1 classifier once at startup, free at shutdown."""
    logger.info("Loading L1 classifier ...")
    clf = L1Classifier(
        block_threshold=settings.l1_block_threshold,
        pass_threshold=settings.l1_pass_threshold,
    )
    l1_classifier.set_instance(clf)
    logger.info("L1 ready.")
    yield
    logger.info("Shutting down.")


app = FastAPI(
    title="AI Firewall Gateway",
    description="LLM Application Security Gateway — Project 4 of Suliman's DevSecOps Portfolio.",
    version="0.2.0",
    lifespan=lifespan,
)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if x_api_key != settings.gateway_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header.")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_id = str(uuid.uuid4())[:8]
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info(
        "req_id=%s method=%s path=%s status=%d elapsed_ms=%.1f",
        request_id, request.method, request.url.path, response.status_code, elapsed_ms,
    )
    response.headers["X-Request-ID"] = request_id
    return response


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    try:
        clf = l1_classifier.get_instance()
        l1_status = L1Status(
            loaded=True,
            f1=clf.metrics.get("f1"),
            block_threshold=clf.block_threshold,
            pass_threshold=clf.pass_threshold,
        )
    except RuntimeError:
        l1_status = L1Status(loaded=False)

    return HealthResponse(
        backends_available=backend_router.available(),
        l1=l1_status,
    )


@app.post(
    "/v1/chat",
    response_model=ChatResponse,
    tags=["chat"],
    dependencies=[Depends(require_api_key)],
)
async def chat(request: ChatRequest) -> ChatResponse:
    # ───────── Layer 1 — XGBoost classifier ─────────
    clf = l1_classifier.get_instance()
    # Run sync ML in a thread so we don't block the event loop
    score, verdict = await asyncio.to_thread(clf.evaluate, request.prompt)
    logger.info(
        "L1 score=%.4f verdict=%s prompt_len=%d backend=%s",
        score, verdict, len(request.prompt), request.backend,
    )

    if verdict == "block":
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Request blocked by AI Firewall (Layer 1).",
                "layer": "L1",
                "score": round(score, 4),
                "threshold": clf.block_threshold,
            },
        )

    # ───────── Forward to backend ─────────
    backend = backend_router.get(request.backend)
    try:
        response = await backend.chat(request)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("backend_error backend=%s", backend.name)
        raise HTTPException(status_code=502, detail=f"Backend error: {e}") from e

    response.firewall = FirewallVerdict(l1_score=round(score, 4), verdict=verdict)
    return response
