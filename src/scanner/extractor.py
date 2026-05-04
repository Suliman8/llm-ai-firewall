"""Content extractor — turns raw text / URL / PDF into plain text.

Each extractor enforces its own safety limits:
- URL: timeout, size cap, blocks private IPs (SSRF defence)
- PDF: size cap, max page count
- TEXT: no extraction needed, just returned

Returns (plain_text, source_label) so downstream code knows where the
content came from — vital when chaining into a RAG pipeline so the LLM
can be told "this is data, not instructions".
"""
from __future__ import annotations

import base64
import io
import ipaddress
import logging
import socket
from typing import Literal
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
from pypdf import PdfReader

logger = logging.getLogger(__name__)

Source = Literal["text", "url", "pdf"]

# --- Safety limits -----------------------------------------------------
URL_FETCH_TIMEOUT_SEC = 5.0
URL_MAX_BYTES = 1_000_000          # 1 MB
PDF_MAX_BYTES = 10_000_000         # 10 MB (after base64 decode)
PDF_MAX_PAGES = 50
ALLOWED_URL_SCHEMES = {"http", "https"}


class ExtractionError(ValueError):
    """Raised when extraction fails or violates a safety limit."""


# ---------------------------------------------------------------- TEXT

def extract_text(text: str) -> tuple[str, str]:
    """Pass-through. Just normalises whitespace."""
    cleaned = " ".join(text.split())
    return cleaned, "raw_text"


# ---------------------------------------------------------------- URL

def _is_private_or_loopback(host: str) -> bool:
    """SSRF defence — refuse any host that resolves to a private/loopback/link-local IP."""
    try:
        # Resolve hostname → IP (handles DNS-rebind by checking after lookup)
        ip_str = socket.gethostbyname(host)
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except (socket.gaierror, ValueError):
        # Can't resolve → safer to refuse
        return True


async def extract_url(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_URL_SCHEMES:
        raise ExtractionError(f"URL scheme '{parsed.scheme}' not allowed")
    if not parsed.hostname:
        raise ExtractionError("URL has no hostname")
    if _is_private_or_loopback(parsed.hostname):
        raise ExtractionError("Refusing to fetch private/loopback host (SSRF protection)")

    async with httpx.AsyncClient(
        timeout=URL_FETCH_TIMEOUT_SEC,
        follow_redirects=True,
        max_redirects=3,
    ) as client:
        try:
            resp = await client.get(url, headers={"User-Agent": "AI-Firewall-Scanner/1.0"})
        except httpx.HTTPError as e:
            raise ExtractionError(f"URL fetch failed: {type(e).__name__}: {e}") from e

        if resp.status_code >= 400:
            raise ExtractionError(f"URL returned HTTP {resp.status_code}")

        body = resp.content[:URL_MAX_BYTES]
        if len(resp.content) > URL_MAX_BYTES:
            logger.warning("URL content truncated to %d bytes", URL_MAX_BYTES)

        ctype = resp.headers.get("content-type", "").lower()
        if "html" in ctype:
            text = _html_to_text(body.decode("utf-8", errors="replace"))
        else:
            # Plain text / JSON / unknown → decode best-effort
            text = body.decode("utf-8", errors="replace")

    return text.strip(), f"url:{parsed.hostname}"


def _html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    # Drop chrome that almost always contains noise
    for tag in soup(["script", "style", "nav", "footer", "header", "noscript"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ").split())


# ---------------------------------------------------------------- PDF

def extract_pdf_b64(pdf_b64: str) -> tuple[str, str]:
    try:
        raw = base64.b64decode(pdf_b64, validate=True)
    except (ValueError, TypeError) as e:
        raise ExtractionError(f"Invalid base64 PDF: {e}") from e

    if len(raw) > PDF_MAX_BYTES:
        raise ExtractionError(f"PDF too large ({len(raw)} > {PDF_MAX_BYTES} bytes)")

    try:
        reader = PdfReader(io.BytesIO(raw))
    except Exception as e:
        raise ExtractionError(f"Could not parse PDF: {type(e).__name__}: {e}") from e

    pages = reader.pages[:PDF_MAX_PAGES]
    parts: list[str] = []
    for i, page in enumerate(pages):
        try:
            parts.append(page.extract_text() or "")
        except Exception as e:
            logger.warning("Skipping unreadable page %d: %s", i, e)

    text = "\n".join(parts).strip()
    return text, f"pdf:{len(pages)}pages"
