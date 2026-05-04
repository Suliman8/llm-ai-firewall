"""Text chunker — splits long content into overlapping windows so each
chunk fits inside L1b's 512-token limit and so we can localise *where*
in a document an injection attempt lives.

We use character counts (not tokens) for simplicity — 400 chars is
roughly 100 tokens for English, well under DeBERTa's 512-token cap.
"""
from __future__ import annotations

from dataclasses import dataclass

DEFAULT_CHUNK_CHARS = 400
DEFAULT_OVERLAP_CHARS = 50
MAX_CHUNKS = 200          # hard cap so a 50-page PDF can't fan us out infinitely


@dataclass(frozen=True)
class Chunk:
    index: int            # 0-based position in the chunk stream
    text: str
    start: int            # char offset in original text
    end: int              # char offset in original text


def chunk_text(
    text: str,
    chunk_size: int = DEFAULT_CHUNK_CHARS,
    overlap: int = DEFAULT_OVERLAP_CHARS,
) -> list[Chunk]:
    """Produce overlapping fixed-size character windows.

    Whitespace-only chunks are dropped. Caps total chunks at MAX_CHUNKS to
    bound work on large documents.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be >= 0 and < chunk_size")

    text = text.strip()
    if not text:
        return []

    if len(text) <= chunk_size:
        return [Chunk(index=0, text=text, start=0, end=len(text))]

    step = chunk_size - overlap
    chunks: list[Chunk] = []
    pos = 0
    while pos < len(text) and len(chunks) < MAX_CHUNKS:
        end = min(pos + chunk_size, len(text))
        piece = text[pos:end].strip()
        if piece:
            chunks.append(Chunk(index=len(chunks), text=piece, start=pos, end=end))
        if end == len(text):
            break
        pos += step

    return chunks
