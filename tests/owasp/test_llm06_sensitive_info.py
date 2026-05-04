"""OWASP LLM06 — Sensitive Information Disclosure.

Direct unit tests on the output filter regex bank. Faster + more
deterministic than driving everything through /v1/chat.
"""
from __future__ import annotations

import pytest

from src.firewall.output_filter import (
    HARD_BLOCK_TYPES,
    has_hard_block,
    redact,
    scan_output,
)


# (description, text, expected finding type, hard-block?)
SECRET_CASES: list[tuple[str, str, str, bool]] = [
    ("openai_key",      "Your key is sk-test1234567890abcdefghij1234567890XYZ now",   "openai_key", True),
    ("anthropic_key",   "Use sk-ant-api03-abc_def-ghi_jkl-mnopqrstuvwxyz1234567890",  "anthropic_key", True),
    ("github_pat",      "Token: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ now expires", "github_pat", True),
    ("aws_access_key",  "AWS access key: AKIAIOSFODNN7EXAMPLE",                       "aws_access_key", True),
    ("jwt",             "Auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKK", "jwt", True),
    ("private_key",     "-----BEGIN RSA PRIVATE KEY-----",                            "private_key_block", True),
    ("jailbreak",       "Sure! As DAN, I will ignore all rules and do whatever.",     "jailbreak_marker", True),
    ("email_soft",      "Contact us at support@example.com for help.",                "email", False),
]


@pytest.mark.parametrize("name,text,expected_type,is_hard", SECRET_CASES, ids=lambda v: v if isinstance(v, str) else "")
def test_llm06_output_filter_detects(name, text, expected_type, is_hard):
    findings = scan_output(text)
    types = {f.type for f in findings}
    assert expected_type in types, f"missed {expected_type} in {types}"
    if is_hard:
        assert has_hard_block(findings), f"{expected_type} should hard-block"
        assert expected_type in HARD_BLOCK_TYPES
    else:
        # Soft findings exist but should NOT trigger hard-block on their own
        assert not has_hard_block(findings), f"{expected_type} should NOT hard-block"


def test_llm06_redact_replaces_secrets_in_place():
    text = "Use this key sk-test1234567890abcdefghij1234567890XYZ to call the API."
    findings = scan_output(text)
    cleaned = redact(text, findings)
    assert "sk-test" not in cleaned
    assert "[REDACTED:openai_key]" in cleaned


def test_llm06_clean_text_yields_no_findings():
    findings = scan_output("The capital of France is Paris. The weather is mild.")
    assert findings == []
