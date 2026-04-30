# 🛡️ LLM Application Security Gateway (AI Firewall)

> A 6-layer defence pipeline that proxies traffic between users and AI models — blocks prompt injection, jailbreaks, and data exfiltration.
>
> **Project 4** of the Advanced DevSecOps Portfolio · by **Suliman Khan**

---

## What it does (one sentence)

It's an **airport security checkpoint for messages going to AI** — every prompt to ChatGPT/Claude/Llama passes through 6 detection layers before the AI ever sees it, and every reply is checked before it leaves.

## Why it exists

Prompt injection is the **#1 threat** in the OWASP LLM Top 10 — and there is no clean structural fix. The only known defence is **layered detection**, which is exactly what this firewall provides.

---

## Architecture

```
USER  →  [ FastAPI Gateway ]  →  [ 6 Detection Layers ]  →  AI MODEL  →  [ Output Check ]  →  USER
```

| Layer | Purpose | Tech |
|-------|---------|------|
| **L1** | Fast malicious-prompt classifier | XGBoost |
| **L2** | Smart semantic check on borderline prompts | LLM-as-judge (Claude / GPT) |
| **L3** | Indirect-injection scan in PDFs, URLs, RAG docs | PyPDF + heuristics |
| **L4** | Canary-token tripwire for data exfiltration | Redis |
| **L5** | Rate limiting per API key | Redis |
| **L6** | OWASP LLM Top-10 regression suite | pytest CI |

📖 See `docs/ARCHITECTURE.md` for full diagrams and design decisions.

---

## Build plan (8 weeks)

| Week | Milestone |
|------|-----------|
| W0 | Environment + project skeleton |
| W1 | FastAPI proxy + LLM backends |
| W2 | XGBoost classifier (L1) |
| W3 | LLM-as-judge (L2) |
| W4 | Document scanner (L3) |
| W5 | Canary tokens (L4) |
| W6 | OWASP test harness (L6) |
| W7 | Self-hosted Llama + rate limiting (L5) |
| W8 | Red-team report + benchmarks |

---

## Project structure

```
P4/
├── src/
│   ├── gateway/      # FastAPI app
│   ├── detectors/    # L1-L4 detection layers
│   ├── backends/     # OpenAI / Anthropic / Llama adapters
│   └── utils/        # shared helpers
├── tests/
│   └── owasp/        # OWASP LLM Top-10 attack tests
├── datasets/         # Lakera Gandalf, HF prompts (gitignored)
├── models/           # trained XGBoost + Llama weights (gitignored)
├── docs/             # architecture diagrams + project overview
├── notebooks/        # Jupyter exploration (XGBoost training)
└── scripts/          # helper bash scripts
```

---

## Tech stack

**Backend:** FastAPI · Uvicorn · Pydantic
**ML:** XGBoost · sentence-transformers · HuggingFace datasets
**LLM:** OpenAI · Anthropic · Llama (Ollama)
**Storage:** Redis · SQLite
**Docs / parsing:** PyPDF · BeautifulSoup · LangChain
**Observability:** OpenTelemetry
**Tests / CI:** pytest · GitHub Actions

---

## Quick start (will work after W1)

```bash
# 1. Clone + enter
git clone <repo-url> && cd P4

# 2. Set up Python env
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Add your API keys
cp .env.example .env
# edit .env and paste your OpenAI + Anthropic keys

# 4. Run the gateway
uvicorn src.gateway.app:app --reload
```

Then open <http://localhost:8000/docs> for the auto-generated API docs.

---

## Status

🚧 **In progress** — currently at **W0** (environment setup).

---

## License

MIT (planned) — for portfolio / educational use.
