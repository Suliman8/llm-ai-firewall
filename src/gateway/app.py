"""FastAPI application — the AI Firewall gateway.

Run with:
    uvicorn src.gateway.app:app --reload --host 0.0.0.0 --port 8000

Layers chained on every /v1/chat call (in order, only when needed):
    L1a XGBoost      ~10 ms   — runs always
        └── if uncertain  ─┐
    L1b ProtectAI    ~50 ms   — runs only when L1a is uncertain
        └── if uncertain  ─┐
    L2 LLM-judge     ~500 ms  — runs only when L1b is also uncertain
"""
import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from src.backends.router import router as backend_router
from src.detectors import l1_classifier, l1b_protectai, l2_llm_judge
from src.detectors.l1_classifier import L1Classifier
from src.detectors.l1b_protectai import L1bProtectAI
from src.detectors.l2_llm_judge import L2LLMJudge
from src.gateway.config import settings
from src.firewall.canary import generate_canary
from src.firewall.output_filter import has_hard_block, redact, scan_output
from src.gateway.schemas import (
    ChatRequest,
    ChatResponse,
    FirewallStatus,
    FirewallVerdict,
    HealthResponse,
    L1aResult,
    L1aStatus,
    L1bResult,
    L1bStatus,
    L2Result,
    L2Status,
    OutputFilterResult,
    OutputFinding,
    ScanChunkResult,
    ScanRequest,
    ScanResponse,
    ScanSummary,
)
from src.scanner.chunker import chunk_text
from src.scanner.extractor import (
    ExtractionError,
    extract_pdf_b64,
    extract_text,
    extract_url,
)
from src.scanner.scan_engine import scan_chunks

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("gateway")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── L1a XGBoost (always required) ──
    logger.info("Loading L1a XGBoost ...")
    l1_classifier.set_instance(
        L1Classifier(
            block_threshold=settings.l1_block_threshold,
            pass_threshold=settings.l1_pass_threshold,
        )
    )

    # ── L1b ProtectAI (always required) ──
    logger.info("Loading L1b ProtectAI ...")
    l1b_protectai.set_instance(L1bProtectAI())

    # ── L2 LLM-judge (optional — degrades gracefully if Groq key missing) ──
    try:
        l2_llm_judge.set_instance(L2LLMJudge(model=settings.groq_model))
        logger.info("L2 LLM-judge ready.")
    except RuntimeError as e:
        logger.warning("L2 disabled: %s", e)

    logger.info("All firewall layers initialized.")
    yield
    logger.info("Shutting down.")


app = FastAPI(
    title="AI Firewall Gateway",
    description="LLM Application Security Gateway — Project 4 of Suliman's DevSecOps Portfolio.",
    version="0.3.0",
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


# ───────── /health ─────────

@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    # L1a
    try:
        l1a = l1_classifier.get_instance()
        l1a_status = L1aStatus(
            loaded=True,
            f1=l1a.metrics.get("f1"),
            block_threshold=l1a.block_threshold,
            pass_threshold=l1a.pass_threshold,
        )
    except RuntimeError:
        l1a_status = L1aStatus(loaded=False)

    # L1b
    l1b_status = L1bStatus(loaded=l1b_protectai.is_loaded())

    # L2
    l2_status = L2Status(
        loaded=l2_llm_judge.is_loaded(),
        model=settings.groq_model if l2_llm_judge.is_loaded() else None,
    )

    return HealthResponse(
        backends_available=backend_router.available(),
        firewall=FirewallStatus(l1a=l1a_status, l1b=l1b_status, l2=l2_status),
    )


# ───────── /v1/chat — chained firewall ─────────

@app.post(
    "/v1/chat",
    response_model=ChatResponse,
    tags=["chat"],
    dependencies=[Depends(require_api_key)],
)
async def chat(request: ChatRequest) -> ChatResponse:
    prompt = request.prompt

    # ── DEMO bypass — only allowed on mock backend ──
    bypass_input = request.bypass_input_firewall and request.backend == "mock"
    if request.bypass_input_firewall and request.backend != "mock":
        logger.warning("bypass_input_firewall ignored: backend=%s (only mock allows it)", request.backend)

    if bypass_input:
        logger.warning("INPUT FIREWALL BYPASSED for demo (backend=mock)")
        fw_l1a = L1aResult(score=0.0, verdict="pass")
        fw_l1b: L1bResult | None = None
        fw_l2: L2Result | None = None
        l1a_score = 0.0
        l1a_v = "pass"
    else:
        # ── L1a XGBoost (always runs) ──
        l1a = l1_classifier.get_instance()
        l1a_score, l1a_v = await asyncio.to_thread(l1a.evaluate, prompt)
        logger.info("L1a score=%.4f verdict=%s", l1a_score, l1a_v)

        fw_l1a = L1aResult(score=round(l1a_score, 4), verdict=l1a_v)
        fw_l1b: L1bResult | None = None
        fw_l2: L2Result | None = None

    if l1a_v == "block":
        firewall = FirewallVerdict(overall="block", blocked_by="L1a", l1a=fw_l1a)
        raise HTTPException(status_code=403, detail={
            "message": "Request blocked by AI Firewall.",
            "blocked_by": "L1a",
            "firewall": firewall.model_dump(),
        })

    # ── L1b ProtectAI (only when L1a is uncertain) ──
    if l1a_v == "uncertain":
        l1b = l1b_protectai.get_instance()
        l1b_score, l1b_v = await asyncio.to_thread(l1b.evaluate, prompt)
        logger.info("L1b score=%.4f verdict=%s", l1b_score, l1b_v)
        fw_l1b = L1bResult(score=round(l1b_score, 4), verdict=l1b_v)

        # ── L2 LLM-judge — fires whenever the verdict is non-trivial ──
        #   1. L1b uncertain                              → ambiguity
        #   2. L1b PASS but L1a high (>= disagreement)    → "L1b is too lenient" disagreement
        #   3. L1b BLOCK                                  → give L2 the chance to override a false-positive
        # Skip L2 only when L1a + L1b confidently agree it's safe (L1b pass + L1a low),
        # in which case we trust the agreement.
        l1b_uncertain = l1b_v == "uncertain"
        strong_disagreement = (
            l1b_v == "pass" and l1a_score >= settings.l1_disagreement_threshold
        )
        l1b_block = l1b_v == "block"

        if (l1b_uncertain or strong_disagreement or l1b_block) and l2_llm_judge.is_loaded():
            trigger = (
                "uncertain" if l1b_uncertain
                else "disagreement" if strong_disagreement
                else "l1b_block_review"
            )
            l2 = l2_llm_judge.get_instance()
            l2_v, l2_conf, l2_reason = await l2.evaluate(prompt)
            logger.info(
                "L2 trigger=%s verdict=%s confidence=%.2f reason=%s",
                trigger, l2_v, l2_conf, l2_reason,
            )
            fw_l2 = L2Result(verdict=l2_v, confidence=l2_conf, reason=l2_reason)

            if l2_v == "block":
                firewall = FirewallVerdict(
                    overall="block", blocked_by="L2",
                    l1a=fw_l1a, l1b=fw_l1b, l2=fw_l2,
                )
                raise HTTPException(status_code=403, detail={
                    "message": "Request blocked by AI Firewall.",
                    "blocked_by": "L2",
                    "firewall": firewall.model_dump(),
                })
            # L2 says PASS — overrides any L1b block
        elif l1b_block:
            # L1b says block AND L2 unavailable → trust L1b's block as the final word
            firewall = FirewallVerdict(overall="block", blocked_by="L1b", l1a=fw_l1a, l1b=fw_l1b)
            raise HTTPException(status_code=403, detail={
                "message": "Request blocked by AI Firewall.",
                "blocked_by": "L1b",
                "firewall": firewall.model_dump(),
            })

    # ── All input layers passed — build canary + forward to backend ──
    canary = generate_canary()
    effective_system = canary.inject(request.system or "")

    backend = backend_router.get(request.backend)
    try:
        response = await backend.chat(request, system_prompt=effective_system)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("backend_error backend=%s", backend.name)
        raise HTTPException(status_code=502, detail=f"Backend error: {e}") from e

    # ── Output-side firewall ──
    raw_findings = scan_output(response.reply)
    canary_tripped = canary.appears_in(response.reply)
    output_blocked = canary_tripped or has_hard_block(raw_findings)

    findings_models = [
        OutputFinding(type=f.type, match_preview=f.match_preview, span=f.span)
        for f in raw_findings
    ]
    output_result = OutputFilterResult(
        blocked=output_blocked,
        canary_tripped=canary_tripped,
        findings=findings_models,
    )

    if output_blocked:
        logger.warning(
            "output_blocked canary_tripped=%s findings=%s",
            canary_tripped, [f.type for f in raw_findings],
        )
        firewall = FirewallVerdict(
            overall="block", blocked_by="output",
            l1a=fw_l1a, l1b=fw_l1b, l2=fw_l2, output=output_result,
        )
        raise HTTPException(status_code=403, detail={
            "message": "Response blocked by AI Firewall (output-side).",
            "blocked_by": "output",
            "firewall": firewall.model_dump(),
        })

    # Soft findings (PII / credit-card / email) → redact in place, don't block
    if raw_findings:
        response.reply = redact(response.reply, raw_findings)

    response.firewall = FirewallVerdict(
        overall="pass", blocked_by=None,
        l1a=fw_l1a, l1b=fw_l1b, l2=fw_l2, output=output_result,
    )
    return response


# ───────── /v1/scan — indirect-injection scanner (W4) ─────────

@app.post(
    "/v1/scan",
    response_model=ScanResponse,
    tags=["scan"],
    dependencies=[Depends(require_api_key)],
)
async def scan(request: ScanRequest) -> ScanResponse:
    """Screen external content (raw text / URL / PDF) for prompt injection
    BEFORE it gets fed into an LLM context.

    Pipeline: extract → chunk → L1a/L1b/L2 per chunk → aggregate.
    """
    try:
        if request.source == "text":
            content, provenance = extract_text(request.text or "")
        elif request.source == "url":
            content, provenance = await extract_url(request.url or "")
        elif request.source == "pdf":
            content, provenance = extract_pdf_b64(request.pdf_b64 or "")
        else:  # pragma: no cover — pydantic enforces
            raise HTTPException(status_code=400, detail=f"Unknown source: {request.source}")
    except ExtractionError as e:
        raise HTTPException(status_code=422, detail=f"Extraction failed: {e}") from e

    if not content:
        raise HTTPException(status_code=422, detail="No extractable text in source.")

    pieces = chunk_text(content)
    records, summary = await scan_chunks(pieces)
    logger.info(
        "scan source=%s provenance=%s chunks=%d blocked=%d overall=%s",
        request.source, provenance, summary["total_chunks"],
        summary["blocked_chunks"], summary["overall"],
    )

    return ScanResponse(
        source=request.source,
        provenance=provenance,
        char_count=len(content),
        summary=ScanSummary(**summary),
        chunks=[ScanChunkResult(**r) for r in records],
    )
