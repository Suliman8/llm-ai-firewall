"""Output filter — regex-based scan of the LLM's reply for secrets,
PII, and jailbreak-success markers.

Why regex for this layer (not ML):
  - These are precise, well-known patterns (key formats, JWTs).
  - Regex is deterministic, fast, and explainable — you can show
    auditors *exactly* what triggered.
  - ML in this slot is overkill and has fuzzy false-positives; the
    request-side detectors already handle ambiguity.

Trade-off: regex is brittle to new key formats; we keep the list
narrow and high-precision rather than wide and noisy.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# --- Patterns -----------------------------------------------------------
# Each entry: (finding_type, compiled_regex, sample_redaction)
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai_key",      re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("anthropic_key",   re.compile(r"sk-ant-[A-Za-z0-9_\-]{30,}")),
    ("github_pat",      re.compile(r"\bgh[pous]_[A-Za-z0-9]{36}\b")),
    ("aws_access_key",  re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key",  re.compile(r"\b[A-Za-z0-9/+=]{40}\b(?=.*aws)", re.IGNORECASE)),
    ("jwt",             re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("email",           re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("credit_card",     re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("jailbreak_marker", re.compile(
        r"(?i)\b(?:as\s+dan,?\s+i\s+will|developer\s+mode\s+enabled|"
        r"jailbreak\s+successful|i\s+am\s+now\s+dan|aim\s+mode\s+activated)\b"
    )),
]

# Findings of these types are HARD blocks — reply gets replaced.
HARD_BLOCK_TYPES = {
    "openai_key", "anthropic_key", "github_pat", "aws_access_key",
    "aws_secret_key", "jwt", "private_key_block", "jailbreak_marker",
}


@dataclass(frozen=True)
class Finding:
    type: str
    match_preview: str   # First 40 chars of the match (truncated for safety)
    span: tuple[int, int]


def scan_output(text: str) -> list[Finding]:
    """Run every regex against the reply; return the list of findings."""
    findings: list[Finding] = []
    if not text:
        return findings
    for finding_type, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            preview = m.group(0)[:40]
            findings.append(Finding(type=finding_type, match_preview=preview, span=m.span()))
    return findings


def has_hard_block(findings: list[Finding]) -> bool:
    return any(f.type in HARD_BLOCK_TYPES for f in findings)


def redact(text: str, findings: list[Finding]) -> str:
    """Replace each finding's span with [REDACTED:<type>]. Right-to-left
    so earlier spans don't shift after replacement."""
    if not findings:
        return text
    out = text
    for f in sorted(findings, key=lambda x: x.span[0], reverse=True):
        start, end = f.span
        out = out[:start] + f"[REDACTED:{f.type}]" + out[end:]
    return out
