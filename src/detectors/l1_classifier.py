"""Layer 1 — XGBoost prompt-injection classifier.

Wraps the trained joblib bundle (embedder + XGBoost) so the gateway can
score prompts without knowing the internal pipeline.

Three verdicts:
    score <= pass_threshold   →  "pass"      — clearly safe
    pass < score < block      →  "uncertain" — pass for now (caught by L2 in W3)
    score >= block_threshold  →  "block"     — clearly malicious
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

import joblib
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = Path("models/xgboost_classifier.joblib")

Verdict = Literal["pass", "uncertain", "block"]


class L1Classifier:
    """Loads a trained model bundle and scores prompts."""

    def __init__(
        self,
        model_path: Path = DEFAULT_MODEL_PATH,
        block_threshold: float = 0.7,
        pass_threshold: float = 0.2,
    ) -> None:
        if not model_path.exists():
            raise FileNotFoundError(
                f"L1 model not found at {model_path}. "
                "Run `python scripts/train_classifier.py` first."
            )
        bundle = joblib.load(model_path)
        self.classifier = bundle["classifier"]
        self.embedder = SentenceTransformer(bundle["embedding_model_name"])
        self.metrics: dict = bundle.get("metrics", {})
        self.block_threshold = block_threshold
        self.pass_threshold = pass_threshold
        logger.info(
            "L1 loaded — F1=%.4f block>=%.2f pass<=%.2f",
            self.metrics.get("f1", 0.0), block_threshold, pass_threshold,
        )

    def score(self, text: str) -> float:
        """Return malicious probability 0.0 - 1.0."""
        emb = self.embedder.encode([text], show_progress_bar=False)
        return float(self.classifier.predict_proba(emb)[0, 1])

    def evaluate(self, text: str) -> tuple[float, Verdict]:
        """Return (score, verdict) where verdict is pass / uncertain / block."""
        s = self.score(text)
        if s >= self.block_threshold:
            return s, "block"
        if s <= self.pass_threshold:
            return s, "pass"
        return s, "uncertain"


# Module-level singleton, set by app.py's lifespan handler at startup.
_instance: L1Classifier | None = None


def set_instance(clf: L1Classifier) -> None:
    global _instance
    _instance = clf


def get_instance() -> L1Classifier:
    if _instance is None:
        raise RuntimeError("L1 classifier not initialized — call set_instance() first.")
    return _instance
