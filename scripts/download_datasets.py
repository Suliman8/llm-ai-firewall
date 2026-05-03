"""Download and merge public prompt-injection datasets.

Run from the project root:
    python scripts/download_datasets.py

Produces:
    datasets/prompt_injection_train.csv
        Two columns: text (the prompt), label (0 = safe, 1 = malicious).

Source datasets (all public, no auth required):
    - deepset/prompt-injections                  (~660 rows, balanced)
    - jackhhao/jailbreak-classification          (~1300 rows, balanced)
    - Lakera/gandalf_ignore_instructions         (~1000 rows, all attacks)
    - xTRam1/safe-guard-prompt-injection         (~10k rows, balanced)
    - rubend18/ChatGPT-Jailbreak-Prompts         (~80 rows, all jailbreaks)
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd
from datasets import load_dataset

OUTPUT_DIR = Path("datasets")
OUTPUT_FILE = OUTPUT_DIR / "prompt_injection_train.csv"


def _all_splits(ds) -> pd.DataFrame:
    """Concat every split (train, test, validation, ...) into one DataFrame."""
    return pd.concat([ds[split].to_pandas() for split in ds.keys()], ignore_index=True)


def _summarize(df: pd.DataFrame, name: str) -> None:
    n_total = len(df)
    n_mal = int(df["label"].sum())
    n_safe = n_total - n_mal
    print(f"  ✓ {name:50s} {n_total:6d} rows  ({n_mal:5d} mal / {n_safe:5d} safe)")


def _pick_col(df: pd.DataFrame, candidates: list[str]) -> str | None:
    """Return the first column name from `candidates` that exists in `df`."""
    return next((c for c in candidates if c in df.columns), None)


def load_deepset() -> pd.DataFrame:
    """deepset/prompt-injections — direct injection examples + safe prompts."""
    ds = load_dataset("deepset/prompt-injections")
    df = _all_splits(ds)[["text", "label"]].copy()
    _summarize(df, "deepset/prompt-injections")
    return df


def load_jailbreak() -> pd.DataFrame:
    """jackhhao/jailbreak-classification — jailbreak vs benign prompts."""
    ds = load_dataset("jackhhao/jailbreak-classification")
    df = _all_splits(ds).rename(columns={"prompt": "text"})
    df["label"] = (df["type"] == "jailbreak").astype(int)
    df = df[["text", "label"]]
    _summarize(df, "jackhhao/jailbreak-classification")
    return df


def load_lakera_gandalf() -> pd.DataFrame:
    """Lakera/gandalf_ignore_instructions — all examples are attack attempts (label=1)."""
    ds = load_dataset("Lakera/gandalf_ignore_instructions")
    raw = _all_splits(ds)
    text_col = _pick_col(raw, ["text", "prompt", "input"])
    if not text_col:
        raise ValueError(f"Unknown schema for Lakera. Cols: {raw.columns.tolist()}")
    df = pd.DataFrame({"text": raw[text_col].astype(str), "label": 1})
    _summarize(df, "Lakera/gandalf_ignore_instructions")
    return df


def load_xtram1() -> pd.DataFrame:
    """xTRam1/safe-guard-prompt-injection — large balanced modern dataset."""
    ds = load_dataset("xTRam1/safe-guard-prompt-injection")
    raw = _all_splits(ds)
    text_col = _pick_col(raw, ["text", "prompt", "content"])
    label_col = _pick_col(raw, ["label", "labels", "is_injection"])
    if not text_col or not label_col:
        raise ValueError(f"Unknown schema for xTRam1. Cols: {raw.columns.tolist()}")
    df = pd.DataFrame({"text": raw[text_col].astype(str), "label": raw[label_col]})
    # Map possible string labels to 0/1
    if df["label"].dtype == object:
        df["label"] = df["label"].map(
            {"injection": 1, "safe": 0, "malicious": 1, "benign": 0,
             "INJECTION": 1, "SAFE": 0, "true": 1, "false": 0,
             "1": 1, "0": 0}
        )
    df["label"] = df["label"].astype(int)
    _summarize(df, "xTRam1/safe-guard-prompt-injection")
    return df


def load_rubend18() -> pd.DataFrame:
    """rubend18/ChatGPT-Jailbreak-Prompts — small but pure jailbreak collection."""
    ds = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts")
    raw = _all_splits(ds)
    text_col = _pick_col(raw, ["Prompt", "prompt", "text"])
    if not text_col:
        raise ValueError(f"Unknown schema for rubend18. Cols: {raw.columns.tolist()}")
    df = pd.DataFrame({"text": raw[text_col].astype(str), "label": 1})
    _summarize(df, "rubend18/ChatGPT-Jailbreak-Prompts")
    return df


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Downloading datasets from HuggingFace ...\n")
    loaders = [
        load_deepset,
        load_jailbreak,
        load_lakera_gandalf,
        load_xtram1,
        load_rubend18,
    ]
    frames: list[pd.DataFrame] = []
    for loader in loaders:
        try:
            frames.append(loader())
        except Exception as e:
            print(f"  ⚠ {loader.__name__} failed: {type(e).__name__}: {e}")

    if not frames:
        raise SystemExit("ERROR: No datasets loaded. Check your internet connection.")

    combined = pd.concat(frames, ignore_index=True)

    # Clean: drop empty / whitespace-only / duplicate prompts
    before = len(combined)
    combined = combined.dropna(subset=["text"])
    combined["text"] = combined["text"].astype(str).str.strip()
    combined = combined[combined["text"].str.len() > 0]
    combined = combined[combined["text"].str.len() < 5000]  # drop huge prompts
    combined = combined.drop_duplicates(subset=["text"]).reset_index(drop=True)
    after = len(combined)

    n_mal = int(combined["label"].sum())
    n_safe = after - n_mal

    print("\n" + "=" * 70)
    print(f"Combined : {before} → {after} rows after dedup")
    print(f"Balance  : {n_mal} malicious  /  {n_safe} safe")
    print(f"Mal ratio: {n_mal / after:.2%}")
    print("=" * 70)

    combined.to_csv(OUTPUT_FILE, index=False)
    size_kb = OUTPUT_FILE.stat().st_size / 1024
    print(f"\n✓ Saved to {OUTPUT_FILE}  ({size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
