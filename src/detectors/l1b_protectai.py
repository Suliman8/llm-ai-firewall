"""Layer 1b — ProtectAI's pre-trained DeBERTa prompt-injection classifier.

Runs ONLY when L1a (XGBoost) is uncertain. Slower (~50 ms) but better at
semantic patterns (DAN, AIM, role-play) that XGBoost misses.

Model card: https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2
"""
from __future__ import annotations

import logging
from typing import Literal

from transformers import pipeline

logger = logging.getLogger(__name__)

MODEL_NAME = "protectai/deberta-v3-base-prompt-injection-v2"
Verdict = Literal["pass", "uncertain", "block"]


class L1bProtectAI:
    def __init__(
        self,
        block_threshold: float = 0.7,
        pass_threshold: float = 0.3,
    ) -> None:
        logger.info("Loading L1b: %s ...", MODEL_NAME)
        self.classifier = pipeline(
            "text-classification",
            model=MODEL_NAME,
            truncation=True,
            max_length=512,
            device=-1,  # CPU
        )
        self.block_threshold = block_threshold
        self.pass_threshold = pass_threshold
        logger.info("L1b ready.")

    def score(self, text: str) -> float:
        """Return INJECTION confidence 0.0 - 1.0 (higher = more malicious)."""
        result = self.classifier(text)[0]
        if result["label"] == "INJECTION":
            return float(result["score"])
        return 1.0 - float(result["score"])

    def evaluate(self, text: str) -> tuple[float, Verdict]:
        s = self.score(text)
        if s >= self.block_threshold:
            return s, "block"
        if s <= self.pass_threshold:
            return s, "pass"
        return s, "uncertain"


_instance: L1bProtectAI | None = None


def set_instance(clf: L1bProtectAI) -> None:
    global _instance
    _instance = clf


def get_instance() -> L1bProtectAI:
    if _instance is None:
        raise RuntimeError("L1b not initialized.")
    return _instance


def is_loaded() -> bool:
    return _instance is not None
