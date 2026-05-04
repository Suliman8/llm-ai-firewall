"""Reads docs/bench_results.json and writes 3 PNG charts to docs/charts/.

  layer_attribution.png   — bar chart: which layer caught what % of attacks
  latency_per_layer.png   — bar chart: median latency for each blocking layer
  coverage_summary.png    — bar chart: block-rate + false-positive rate

Usage:
    python scripts/render_charts.py
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # no display needed
import matplotlib.pyplot as plt

BENCH_PATH = Path("docs/bench_results.json")
OUT_DIR = Path("docs/charts")


def load() -> dict:
    if not BENCH_PATH.exists():
        raise SystemExit(f"Run scripts/benchmark.py first — {BENCH_PATH} missing")
    return json.loads(BENCH_PATH.read_text())


def chart_layer_attribution(summary: dict, out: Path) -> None:
    bd = summary["blocked_by_breakdown"]
    labels = ["L1a (XGBoost)", "L1b (DeBERTa)", "L2 (Llama)", "Missed"]
    values = [bd.get("L1a", 0), bd.get("L1b", 0), bd.get("L2", 0), bd.get("missed", 0)]
    colors = ["#2E7D32", "#1565C0", "#6A1B9A", "#C62828"]

    fig, ax = plt.subplots(figsize=(7, 4.2))
    bars = ax.bar(labels, values, color=colors)
    for bar, v in zip(bars, values):
        if v:
            ax.text(bar.get_x() + bar.get_width() / 2, v + 0.05, str(v),
                    ha="center", va="bottom", fontsize=10)
    ax.set_ylabel("Attacks blocked")
    ax.set_title("Layer Attribution — which detector caught what")
    ax.set_ylim(0, max(values) + 1.5 if values else 1)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out, dpi=130)
    plt.close(fig)
    print(f"  wrote {out}")


def chart_latency_per_layer(summary: dict, out: Path) -> None:
    lbl = summary.get("latency_by_blocked_layer", {})
    layers = ["L1a", "L1b", "L2", "passed"]
    p50 = [lbl.get(l, {}).get("p50_ms", 0) for l in layers]
    p95 = [lbl.get(l, {}).get("p95_ms", 0) for l in layers]
    p99 = [lbl.get(l, {}).get("p99_ms", 0) for l in layers]
    pretty = ["Block at L1a", "Block at L1b", "Block at L2", "Allowed"]

    x = range(len(layers))
    width = 0.27

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar([i - width for i in x], p50, width, label="p50", color="#1976D2")
    ax.bar(list(x), p95, width, label="p95", color="#FB8C00")
    ax.bar([i + width for i in x], p99, width, label="p99", color="#C62828")
    ax.set_xticks(list(x))
    ax.set_xticklabels(pretty)
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Per-Layer Latency (lower is better)")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out, dpi=130)
    plt.close(fig)
    print(f"  wrote {out}")


def chart_coverage_summary(summary: dict, out: Path) -> None:
    t = summary["totals"]
    block_rate = t["block_rate_pct"]
    fp_rate = t["false_positive_rate_pct"]
    correct_safe_rate = 100 - fp_rate

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(
        ["Attacks blocked\n(higher is better)", "Safe prompts allowed\n(higher is better)"],
        [block_rate, correct_safe_rate],
        color=["#2E7D32", "#00897B"],
    )
    for bar, v in zip(bars, [block_rate, correct_safe_rate]):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 1, f"{v:.1f}%",
                ha="center", va="bottom", fontsize=12, fontweight="bold")
    ax.set_ylim(0, 110)
    ax.set_ylabel("Rate (%)")
    ax.set_title("Coverage summary — both halves of the firewall contract")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out, dpi=130)
    plt.close(fig)
    print(f"  wrote {out}")


def main() -> None:
    data = load()
    summary = data["summary"]
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Rendering charts:")
    chart_layer_attribution(summary, OUT_DIR / "layer_attribution.png")
    chart_latency_per_layer(summary, OUT_DIR / "latency_per_layer.png")
    chart_coverage_summary(summary, OUT_DIR / "coverage_summary.png")
    print("Done.")


if __name__ == "__main__":
    main()
