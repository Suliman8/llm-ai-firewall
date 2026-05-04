"""Scan engine — runs the existing L1a / L1b / L2 detectors on every
chunk of an extracted document.

Re-uses the firewall layers built in W2 (XGBoost) and W3 (ProtectAI +
LLM-judge). The only new logic here is:
  - per-chunk fan-out
  - a parallel L2 burst for any chunks that need it
  - aggregation: any single blocked chunk → overall block
"""
from __future__ import annotations

import asyncio
import logging
from typing import Literal

from src.detectors import l1_classifier, l1b_protectai, l2_llm_judge
from src.gateway.config import settings
from src.scanner.chunker import Chunk

logger = logging.getLogger(__name__)

ChunkVerdict = Literal["pass", "uncertain", "block"]


async def _scan_chunk(chunk: Chunk) -> dict:
    """Evaluate a single chunk through L1a → L1b → L2 (smart escalation).

    Returns a dict shaped like the per-chunk piece of ScanResponse.
    L2 is *not* invoked here — we collect the chunks that need L2 and
    fire them in parallel later (faster + bounded).
    """
    l1a = l1_classifier.get_instance()
    l1a_score, l1a_v = await asyncio.to_thread(l1a.evaluate, chunk.text)

    record: dict = {
        "index": chunk.index,
        "start": chunk.start,
        "end": chunk.end,
        "preview": chunk.text[:120],
        "l1a": {"score": round(l1a_score, 4), "verdict": l1a_v},
        "l1b": None,
        "l2": None,
        "needs_l2": False,
        "verdict": l1a_v,
        "blocked_by": None,
    }

    if l1a_v == "block":
        record["blocked_by"] = "L1a"
        return record

    if l1a_v == "pass":
        return record

    # L1a uncertain → run L1b
    l1b = l1b_protectai.get_instance()
    l1b_score, l1b_v = await asyncio.to_thread(l1b.evaluate, chunk.text)
    record["l1b"] = {"score": round(l1b_score, 4), "verdict": l1b_v}

    if l1b_v == "block":
        record["verdict"] = "block"
        record["blocked_by"] = "L1b"
        return record

    # Same disagreement rule as /v1/chat
    l1b_uncertain = l1b_v == "uncertain"
    strong_disagreement = (
        l1b_v == "pass" and l1a_score >= settings.l1_disagreement_threshold
    )
    if (l1b_uncertain or strong_disagreement) and l2_llm_judge.is_loaded():
        record["needs_l2"] = True
        record["verdict"] = "uncertain"
    else:
        # No L2 available or no escalation needed → trust L1b
        record["verdict"] = l1b_v

    return record


async def _run_l2_for(chunk: Chunk) -> dict:
    """Fire L2 for one chunk; never raises (always returns a dict)."""
    l2 = l2_llm_judge.get_instance()
    l2_v, l2_conf, l2_reason = await l2.evaluate(chunk.text)
    return {"verdict": l2_v, "confidence": l2_conf, "reason": l2_reason}


async def scan_chunks(chunks: list[Chunk]) -> tuple[list[dict], dict]:
    """Evaluate every chunk; return (per_chunk_records, summary).

    summary = {
        "total_chunks": int,
        "blocked_chunks": int,
        "overall": "pass" | "block",
        "blocked_by": "L1a" | "L1b" | "L2" | None,
    }
    """
    if not chunks:
        return [], {"total_chunks": 0, "blocked_chunks": 0, "overall": "pass", "blocked_by": None}

    # Pass 1: L1a + L1b on every chunk in parallel
    records = await asyncio.gather(*(_scan_chunk(c) for c in chunks))

    # Pass 2: collect chunks that still need L2, run them concurrently
    pending = [(rec, chunks[rec["index"]]) for rec in records if rec.get("needs_l2")]
    if pending:
        l2_results = await asyncio.gather(*(_run_l2_for(c) for _, c in pending))
        for (rec, _chunk), l2_data in zip(pending, l2_results):
            rec["l2"] = l2_data
            rec["verdict"] = "block" if l2_data["verdict"] == "block" else "pass"
            if l2_data["verdict"] == "block":
                rec["blocked_by"] = "L2"

    # Aggregate
    blocked = [r for r in records if r["verdict"] == "block"]
    overall = "block" if blocked else "pass"
    blocked_by = blocked[0]["blocked_by"] if blocked else None

    summary = {
        "total_chunks": len(records),
        "blocked_chunks": len(blocked),
        "overall": overall,
        "blocked_by": blocked_by,
    }
    return records, summary
