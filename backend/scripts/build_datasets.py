"""
scripts/build_datasets.py

Pulls real examples from public research datasets and reshapes them into
the {text,cluster_id,cluster_name} / {text} format the gateway expects,
so you can retrain the Layer C classifier on real data instead of the
toy/template examples shipped in data/.

Sources:
  1. HackAPrompt      — gated, requires a Hugging Face account + accepting
     (attack)            the dataset's terms on the web page first, plus
                         an HF token. Real attacker-submitted injection text.
  2. JailbreakBench    — public, no login needed. NOTE: this dataset is
     (attack)            harmful-behavior REQUESTS ("write a phishing email"),
                         not injection-override PHRASING ("ignore previous
                         instructions"). Written to a separate CSV
                         (harmful_behaviors.csv) rather than merged into
                         attacks.csv, since mixing attack styles without
                         labeling them separately would blur what your
                         rule engine and semantic engine are each supposed
                         to catch. You decide whether/how to merge them.
  3. Stanford Alpaca   — public, no login needed, stdlib-only download
     (benign)            (no `datasets` package required). 52K general
                         instruction-following prompts (CC BY-NC 4.0,
                         research use only) — real benign traffic to
                         counter attacks.csv's much larger row count.

PromptInject and the Lakera PINT benchmark are NOT handled here:
  - PromptInject is a template-assembly framework (`pip install promptinject`),
    not a flat dataset — see the README section on it for a manual snippet.
  - The PINT benchmark dataset itself is private/proprietary (Lakera does
    this deliberately to prevent tools from overfitting to it). There is
    nothing to download; it's a scoring methodology, not a corpus.

Usage:
    pip install datasets huggingface_hub --break-system-packages   # only for jbb/hackaprompt
    huggingface-cli login          # only needed for HackAPrompt

    # No --limit flag = fetch the FULL dataset for that source
    python -m scripts.build_datasets --source jbb
    python -m scripts.build_datasets --source hackaprompt
    python -m scripts.build_datasets --source alpaca
    python -m scripts.build_datasets --source all --merge

    # Pass --limit to cap rows instead (e.g. for a quick sample)
    python -m scripts.build_datasets --source hackaprompt --limit 500
"""
import argparse
import csv
import json
import os
import random
import sys
import urllib.request

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(BACKEND_DIR)
sys.path.insert(0, REPO_ROOT)
import config


def build_jbb_behaviors(limit=None):
    """Public, no auth. Returns harmful-behavior REQUEST text (not
    injection-override phrasing) — written to its own CSV."""
    try:
        from datasets import load_dataset
    except ImportError:
        print("Missing dependency. Run: pip install datasets huggingface_hub --break-system-packages")
        return []

    print("Loading JailbreakBench/JBB-Behaviors ...")
    ds = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")

    rows = []
    for i, row in enumerate(ds):
        if limit and i >= limit:
            break
        rows.append({
            "text": row["Goal"],
            "cluster_id": row["Category"],
            "cluster_name": row["Category"],
        })

    out_path = os.path.join(config.DATA_DIR, "harmful_behaviors.csv")
    _write_csv(out_path, rows)
    print(f"Wrote {len(rows)} rows to {out_path}")
    print("These are harmful-behavior REQUESTS, not injection-override phrasing.")
    print("Review before merging into attacks.csv — see the README note.")
    return rows


def build_hackaprompt(limit=None):
    """Gated dataset. Requires:
      1. Logging into huggingface.co and clicking 'agree' on
         https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset
      2. Running `huggingface-cli login` locally (or setting HF_TOKEN)
    Returns real attacker-submitted injection text (user_input column).

    limit=None (the default, i.e. no --limit flag passed) fetches every
    row in the dataset -- there are ~600K raw submissions, so this can
    take a while and will produce a large hackaprompt_attacks.csv after
    dedup. Pass an explicit --limit if you want a quick sample instead.
    """
    try:
        from datasets import load_dataset
    except ImportError:
        print("Missing dependency. Run: pip install datasets huggingface_hub --break-system-packages")
        return []

    print("Loading hackaprompt/hackaprompt-dataset (gated) ...")
    if limit is None:
        print("No --limit given: fetching the FULL dataset (~600K rows before "
              "dedup). This can take several minutes.")
    try:
        ds = load_dataset("hackaprompt/hackaprompt-dataset", split="train", streaming=True)
    except Exception as e:
        print(f"Could not load HackAPrompt: {e}")
        print("Make sure you've accepted the dataset terms at:")
        print("  https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset")
        print("and are logged in via `huggingface-cli login` (or HF_TOKEN env var).")
        return []

    rows = []
    seen = set()
    for i, row in enumerate(ds):
        if limit is not None and len(rows) >= limit:
            break
        text = (row.get("user_input") or "").strip()
        # Skip empty / duplicate / very short submissions.
        if not text or len(text) < 8 or text in seen:
            continue
        seen.add(text)
        rows.append({
            "text": text,
            "cluster_id": row.get("level", "unlabeled"),
            "cluster_name": f"HackAPrompt level {row.get('level', '?')}",
        })

    out_path = os.path.join(config.DATA_DIR, "hackaprompt_attacks.csv")
    _write_csv(out_path, rows)
    print(f"Wrote {len(rows)} rows to {out_path}")
    print("Review, then merge the rows you want into attacks.csv.")
    return rows


def _write_csv(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "cluster_id", "cluster_name"])
        writer.writeheader()
        writer.writerows(rows)


def merge_into_attacks_csv(*csv_paths):
    """Appends rows from the given CSVs into data/attacks.csv, skipping
    exact-duplicate text. Run this only after you've reviewed the
    intermediate files — some rows (e.g. very short or empty submissions)
    are still worth spot-checking manually before they feed the classifier."""
    import pandas as pd

    existing = pd.read_csv(config.ATTACK_CORPUS_PATH)
    seen_texts = set(existing["text"].astype(str))

    frames = [existing]
    for path in csv_paths:
        if not os.path.exists(path):
            continue
        df = pd.read_csv(path)
        df = df[~df["text"].astype(str).isin(seen_texts)]
        seen_texts.update(df["text"].astype(str))
        frames.append(df)

    merged = pd.concat(frames, ignore_index=True)
    merged.to_csv(config.ATTACK_CORPUS_PATH, index=False)
    print(f"attacks.csv now has {len(merged)} rows (was {len(existing)}).")


def build_alpaca_benign(limit=None):
    """Public, no auth, no `datasets` package needed. Downloads the
    Stanford Alpaca instruction set (52K general instruction-following
    prompts -- cooking, coding, writing, trivia, etc.) and samples a
    subset as REAL benign traffic. This is what actually fixes the
    class imbalance: attacks.csv has ~2300 rows, so hand-written benign
    templates alone don't come close -- real, independently-authored
    instruction data does.

    limit=None (the default, i.e. no --limit flag passed) keeps every
    one of the ~52K instructions after dedup/cleaning.

    License note: Alpaca's data is CC BY-NC 4.0 (research/non-commercial
    use only) -- fine for a hackathon/research prototype, but flag it if
    this ever ships commercially.
    Source: https://github.com/tatsu-lab/stanford_alpaca
    """
    url = "https://raw.githubusercontent.com/tatsu-lab/stanford_alpaca/main/alpaca_data.json"
    print(f"Downloading Alpaca instructions from {url} ...")
    if limit is None:
        print("No --limit given: keeping the FULL ~52K instruction set after dedup.")
    with urllib.request.urlopen(url) as resp:
        data = json.load(resp)

    rng = random.Random(42)
    rng.shuffle(data)

    rows, seen = [], set()
    for entry in data:
        if limit is not None and len(rows) >= limit:
            break
        text = (entry.get("instruction") or "").strip()
        extra_input = (entry.get("input") or "").strip()
        if extra_input:
            text = f"{text} {extra_input}"
        if not text or len(text) < 8 or text in seen:
            continue
        seen.add(text)
        rows.append({"text": text})

    out_path = os.path.join(config.DATA_DIR, "alpaca_benign.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out_path}")
    print("Review, then merge into data/benign.csv with merge_into_benign_csv().")
    return rows


def merge_into_benign_csv(*csv_paths):
    """Appends rows from the given CSVs into data/benign.csv, skipping
    exact-duplicate text -- same pattern as merge_into_attacks_csv."""
    import pandas as pd

    existing = pd.read_csv(config.BENIGN_CORPUS_PATH)
    seen_texts = set(existing["text"].astype(str))

    frames = [existing]
    for path in csv_paths:
        if not os.path.exists(path):
            continue
        df = pd.read_csv(path)
        df = df[~df["text"].astype(str).isin(seen_texts)]
        seen_texts.update(df["text"].astype(str))
        frames.append(df)

    merged = pd.concat(frames, ignore_index=True)
    merged.to_csv(config.BENIGN_CORPUS_PATH, index=False)
    print(f"benign.csv now has {len(merged)} rows (was {len(existing)}).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", choices=["jbb", "hackaprompt", "alpaca", "all"], default="alpaca")
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Cap the number of rows fetched per source. Omit this flag "
             "entirely (the default) to fetch the FULL dataset for each "
             "source instead of a sample.",
    )
    parser.add_argument("--merge", action="store_true", help="merge results directly into the matching corpus CSV")
    args = parser.parse_args()

    attack_written = []
    benign_written = []

    if args.source in ("jbb", "all"):
        build_jbb_behaviors(limit=args.limit)
        attack_written.append(os.path.join(config.DATA_DIR, "harmful_behaviors.csv"))
    if args.source in ("hackaprompt", "all"):
        build_hackaprompt(limit=args.limit)
        attack_written.append(os.path.join(config.DATA_DIR, "hackaprompt_attacks.csv"))
    if args.source in ("alpaca", "all"):
        build_alpaca_benign(limit=args.limit)
        benign_written.append(os.path.join(config.DATA_DIR, "alpaca_benign.csv"))

    if args.merge:
        if attack_written:
            merge_into_attacks_csv(*attack_written)
        if benign_written:
            merge_into_benign_csv(*benign_written)
    elif attack_written or benign_written:
        print("\nRun again with --merge once you've reviewed the output files, "
              "to fold them into the matching data/*.csv.")