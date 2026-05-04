# 🛡️ LLM Application Security Gateway (AI Firewall)

> A FastAPI-based security proxy that sits between users and Large Language Models. Blocks prompt injection, jailbreaks, system-prompt extraction, and secret leaks using a layered defence pipeline.
>
> **Project 4** of the Advanced DevSecOps Portfolio · by **Suliman Khan**
> **Status:** v1.0.0 · Released

---

## TL;DR

| Metric | Result |
|--------|--------|
| 🛡️ **Attacks blocked** | **100 %** (10/10 curated OWASP attacks) |
| ✅ **False-positive rate** | **0 %** (10/10 safe + borderline-safe prompts pass) |
| ⚡ **p95 latency** | **~654 ms** (most requests served in < 75 ms; only borderline cases pay L2 cost) |
| 🧪 **Regression tests** | **53 / 53 passing** across OWASP LLM01/02/03/04/06 |
| 🔌 **Backends supported** | OpenAI · Anthropic · Groq · **Local Ollama (air-gapped)** |
| 🚦 **DoS protection** | Token-bucket rate limiter (Redis, atomic Lua) — proven 60 served / 40 rate-limited at 100 RPS burst |

📖 **[Read the full red-team report →](docs/redteam_report.md)**
📊 **[Coverage table (machine-generated) →](docs/owasp_report.md)**
📑 **Per-week build logs:** [`docs/W0.md`](docs/W0.md) … [`docs/W8.md`](docs/W8.md)

---

## What it does

Every prompt sent to ChatGPT / Claude / Llama through this gateway passes through a chained detection pipeline **before** the LLM ever sees it. Every reply is scanned **before** it leaves the gateway. The system is **provider-agnostic** — works with cloud APIs and a self-hosted local Llama.

```
USER → [ Rate Limiter ] → [ L1a XGBoost ] → [ L1b DeBERTa ] → [ L2 Llama-judge ] → [ Backend LLM ] → [ Output Filter + Canary ] → USER
```

Cheap layers run first. Expensive smart layers run only when needed.

---

## Architecture

| Layer | Tech | Latency | Catches |
|-------|------|---------|---------|
| **L1a** Statistical | XGBoost on 384-dim sentence embeddings | ~10 ms | Obvious attacks (DAN, "ignore previous", AIM) |
| **L1b** Semantic | ProtectAI DeBERTa-v3-prompt-injection-v2 | ~50 ms | Novel role-play, base64-encoded attacks |
| **L2** Reasoning | Llama-3.1-8b-instant via Groq (LLM-as-judge) | ~300 ms | Final arbiter on ambiguous cases; vetoes L1b false-positives |
| **Disagreement escalation** | If L1a high & L1b low → L2 | — | Persona-flips, subtle attacks |
| **Canary token** | Per-request random tag in system prompt | ~0 ms | Successful system-prompt extraction |
| **Output filter** | Regex bank for API keys / JWTs / PII / jailbreak markers | ~1 ms | Secret echoes; off-policy replies |
| **Rate limiter** | Token bucket (Redis atomic Lua + in-memory fallback) | ~1 ms | Per-key DoS (LLM04) |
| **`/v1/scan` endpoint** | Same L1a/L1b/L2 chunked over external content | varies | LLM03 — attacks hidden in PDFs / URLs / RAG docs |

📖 Full design rationale → [`docs/redteam_report.md`](docs/redteam_report.md)

---

## Coverage charts

### Both halves of the firewall contract

![Coverage Summary](docs/charts/coverage_summary.png)

### Layer attribution — which detector caught what

![Layer Attribution](docs/charts/layer_attribution.png)

The Swiss-cheese principle in action: 5 attacks died at L1a (cheap), 5 escalated through L1b → L2 (smart). Zero missed.

### Latency per blocking layer

![Latency Per Layer](docs/charts/latency_per_layer.png)

p50 of an L1a-block is ~44 ms. An L2-escalated block is ~579 ms. Most requests pay the cheap path; only the borderline ones cost more.

---

## OWASP LLM Top-10 coverage

| Risk | Coverage | Mechanism |
|------|----------|-----------|
| LLM01 — Prompt Injection (direct) | ✅ Full | L1a + L1b + L2 chained with disagreement escalation |
| LLM02 — Insecure Output Handling | ✅ Full | Canary token + regex output filter |
| LLM03 — Indirect Injection | ✅ Full | `/v1/scan` (chunked text/URL/PDF) + SSRF defence |
| LLM04 — Model DoS | ✅ Full | Token-bucket rate limiter + Pydantic input caps |
| LLM06 — Sensitive Info Disclosure | ✅ Full | Output filter HARD-blocks API keys / JWTs / private keys; redacts PII |
| LLM05 / 07 / 08 / 09 / 10 | ⚪ Out of scope | See report — not runtime-firewall concerns |

5 of 5 in-scope risks: **100 %** coverage.

---

## Quickstart

```bash
# 1. Clone + venv
git clone https://github.com/Suliman8/llm-ai-firewall && cd llm-ai-firewall
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env — minimum: GATEWAY_API_KEY (any random string)
# Optional: GROQ_API_KEY for L2 LLM-judge (free tier at console.groq.com)
# Optional: OPENAI_API_KEY / ANTHROPIC_API_KEY for those backends

# 3. (Optional) Local Llama via Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:3b

# 4. (Optional) Redis for distributed rate-limit
sudo apt install -y redis-server && sudo systemctl start redis-server

# 5. Train the L1 classifier (~3 min, downloads ~12k prompts)
python scripts/download_datasets.py
python scripts/train_classifier.py

# 6. Run the gateway
uvicorn src.gateway.app:app --reload --host 0.0.0.0 --port 8000
```

OpenAPI docs at <http://localhost:8000/docs>.

### Sample request

```bash
curl -X POST http://localhost:8000/v1/chat \
  -H "X-API-Key: dev-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"backend":"ollama","prompt":"What is the capital of France?"}'
```

Response includes the full firewall verdict per layer:

```json
{
  "backend": "ollama",
  "model": "llama3.2:3b",
  "reply": "The capital of France is Paris.",
  "firewall": {
    "overall": "pass",
    "l1a": {"score": 0.014, "verdict": "pass"},
    "l1b": null,
    "l2":  null,
    "output": {"blocked": false, "canary_tripped": false, "findings": []}
  }
}
```

---

## Run the test suite

```bash
pytest tests/owasp -v
# → 53 passed in ~22 s
```

Generate a fresh markdown coverage report:

```bash
python scripts/owasp_report.py
# → docs/owasp_report.md
```

Run the live benchmark + render charts:

```bash
python scripts/benchmark.py
python scripts/render_charts.py
# → docs/bench_results.json + docs/charts/*.png
```

---

## Project structure

```
P4/
├── src/
│   ├── gateway/      # FastAPI app, schemas, config
│   ├── detectors/    # L1a XGBoost, L1b DeBERTa, L2 Llama-judge
│   ├── scanner/      # /v1/scan: extractor + chunker + scan engine
│   ├── firewall/     # canary, output filter, rate limiter
│   └── backends/     # mock / openai / anthropic / ollama
├── tests/
│   ├── owasp/        # 53 OWASP LLM Top-10 attack tests
│   └── fixtures/     # clean.pdf + poisoned.pdf for indirect-injection tests
├── scripts/
│   ├── download_datasets.py   # 5 HF prompt-injection datasets
│   ├── train_classifier.py    # XGBoost + augmentation
│   ├── benchmark.py           # latency + verdict per layer
│   ├── render_charts.py       # matplotlib charts
│   └── owasp_report.py        # markdown coverage table
├── datasets/
│   └── manual_augmentation.csv  # 68 hand-crafted attack + safe examples
├── docs/
│   ├── W0.md … W8.md          # per-week learning logs
│   ├── redteam_report.md      # executive summary + lessons
│   ├── owasp_report.md        # auto-generated coverage table
│   ├── bench_results.json     # raw benchmark data
│   └── charts/                # PNG charts
├── pytest.ini
└── README.md
```

---

## Tech stack

- **Backend:** FastAPI · Uvicorn · Pydantic · pydantic-settings
- **ML:** XGBoost · sentence-transformers (all-MiniLM-L6-v2) · transformers (DeBERTa-v3) · scikit-learn
- **LLMs:** OpenAI SDK · Anthropic SDK · Groq (Llama-3.1-8b-instant via OpenAI-compat) · Ollama (Llama-3.2-3b local)
- **Storage:** Redis (rate limit + future LRU)
- **Doc parsing:** pypdf · BeautifulSoup4
- **HTTP:** httpx (async)
- **Tests:** pytest · pytest-asyncio · asgi-lifespan · pytest-json-report
- **Charts:** matplotlib

---

## What this is NOT

Honest scoping matters:

- ❌ Not a training-time defence (LLM03 strict reading)
- ❌ Not a tool/plugin sandbox (LLM07/08)
- ❌ Not multilingual — English-only training corpus
- ❌ Not streaming-aware — output filter doesn't yet handle SSE

See [`docs/redteam_report.md`](docs/redteam_report.md) for the full "what we'd ship next" list.

---

## License

MIT — for portfolio, educational, and research use.

---

## Acknowledgments

- ProtectAI for [`deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2)
- Lakera for the Gandalf prompt corpus
- HuggingFace datasets contributors: deepset, jackhhao, xTRam1, rubend18
- OWASP for the LLM Top-10 framework
