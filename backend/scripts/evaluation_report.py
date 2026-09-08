"""
scripts/evaluation_report.py

Consolidates the three pieces of evidence a reviewer usually asks for
(feasibility, false-positive rate, latency) into one Markdown artifact,
pulling numbers from the SAME sources the codebase already produces
instead of re-deriving anything:

  - Feasibility  -> models/threshold.json (precision/recall/AUC on the
                    held-out, leakage-safe test split from models/train.py)
  - False positives -> a live run of the dual-corpus stress test
                    (benign.csv + trigger_benign.csv), same logic as
                    api/dashboard.py's /stress-test endpoint
  - Latency      -> reports/latency_table.csv (written by
                    scripts/benchmark_latency.py)

Run with (from backend/), after training and after benchmark_latency has
been run at least once:

    python -m models.train
    python -m scripts.benchmark_latency
    python -m scripts.evaluation_report

Fast/smoke-test run (capped semantic index + capped stress-test sample):

    python -m scripts.evaluation_report --fast

Writes backend/reports/evaluation_report.md — paste straight into a
paper/pitch "Evaluation" section or a response-to-reviewers letter.
"""
import argparse
import csv
import json
import os
import sys
import time

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(BACKEND_DIR)
sys.path.insert(0, REPO_ROOT)

import pandas as pd

import config
from core.pipeline import detect
from core.semantic_engine import SemanticEngine

REPORTS_DIR = os.path.join(config.BASE_DIR, "reports")
OUT_PATH = os.path.join(REPORTS_DIR, "evaluation_report.md")


def _load_threshold():
    path = os.path.join(config.MODEL_DIR, "threshold.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def _load_latency():
    path = os.path.join(REPORTS_DIR, "latency_table.csv")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        rows = list(csv.DictReader(f))
    return rows[0] if rows else None


def _run_stress_test(sample_size=None):
    """Same over-defense check as api/dashboard.py's /stress-test, run
    directly (no server needed) so this script is self-contained.

    sample_size: if set, caps how many benign/trigger prompts get run
    through detect(). Each call to detect() encodes one prompt at a time
    (no batching, unlike training), so looping over all ~52k benign.csv
    rows one-by-one is itself slow independent of the semantic index size
    -- --fast caps this list too, not just the semantic index.
    """
    general = pd.read_csv(config.BENIGN_CORPUS_PATH)["text"].astype(str).tolist()
    trigger = pd.read_csv(config.TRIGGER_BENIGN_CORPUS_PATH)["text"].astype(str).tolist()
    if sample_size:
        general = general[:sample_size]
        trigger = trigger[:sample_size]
    print(f"  stress-testing {len(general)} general-benign + {len(trigger)} trigger-benign prompts "
          f"(one detect() call per prompt)...", flush=True)

    def _rate(prompts, label):
        if not prompts:
            return 0, 0, 0.0
        flagged = 0
        t0 = time.time()
        for i, p in enumerate(prompts, 1):
            if detect(p, session_id=None, source="user_message").action != "pass":
                flagged += 1
            if i % 500 == 0 or i == len(prompts):
                elapsed = time.time() - t0
                rate = i / elapsed if elapsed > 0 else 0.0
                eta = (len(prompts) - i) / rate if rate > 0 else 0.0
                print(f"    [{label}] {i}/{len(prompts)} ({rate:.0f}/s, eta {eta:.0f}s)", flush=True)
        return flagged, len(prompts), round(flagged / len(prompts), 4)

    g_flagged, g_total, g_rate = _rate(general, "general")
    t_flagged, t_total, t_rate = _rate(trigger, "trigger")
    overall = round((g_flagged + t_flagged) / max(1, g_total + t_total), 4)
    return {
        "general_total": g_total, "general_flagged": g_flagged, "general_rate": g_rate,
        "trigger_total": t_total, "trigger_flagged": t_flagged, "trigger_rate": t_rate,
        "overall_rate": overall,
    }


def _write_report(threshold, latency, stress, fast_mode=False):
    lines = []
    lines.append("# Aegis — Evaluation Report (Feasibility / False-Positive Rate / Latency)\n")
    if fast_mode:
        lines.append(
            "> **NOTE: generated with `--fast`/`--sample-size`** -- the semantic index and "
            "stress-test sample were capped for a quick smoke test. Re-run without that flag "
            "before citing these numbers anywhere (paper, PRD, pitch).\n"
        )
    lines.append(
        "Generated from `models/threshold.json`, `reports/latency_table.csv`, and a "
        "live run of the benign + benign-trigger-word stress test. All numbers below "
        "come from held-out data the classifier was never trained or indexed on "
        "(see `models/train.py`'s leakage-safe split).\n"
    )

    lines.append("## 1. Feasibility\n")
    if threshold:
        lines.append(
            f"- Classifier reaches **precision {threshold['precision_at_threshold']:.3f}** / "
            f"**recall {threshold['recall_at_threshold']:.3f}** on the held-out test split "
            f"at the auto-calibrated threshold (`class_weight={threshold['class_weight']}`).\n"
            f"- Recall by attack category: "
            + ", ".join(f"{k}={v:.3f}" for k, v in threshold.get("recall_by_category", {}).items())
            + ".\n"
            "- The full pipeline (rule engine -> SBERT semantic layer -> classifier -> "
            "drift tracker -> severity gate -> sanitize/pass/block) runs end to end on "
            "real data pulled from public sources (Stanford Alpaca for benign traffic, "
            "JBB-Behaviors / HackAPrompt-derived corpora for attacks), not only "
            "hand-written placeholder examples.\n"
            "- This demonstrates feasibility as: (a) the architecture is implementable "
            "and measurable end to end, and (b) it generalizes to held-out real prompts "
            "rather than only the examples it was tuned on.\n"
        )
    else:
        lines.append(
            "- Run `python -m models.train` first — this writes `models/threshold.json` "
            "with precision/recall/AUC on the held-out split.\n"
        )

    lines.append("## 2. False-Positive Rate\n")
    lines.append(
        f"- General benign set: {stress['general_flagged']}/{stress['general_total']} flagged "
        f"(**FP rate {stress['general_rate']:.2%}**).\n"
        f"- Benign trigger-word set (contains words like \"ignore\", \"system\", \"secret\" in "
        f"ordinary sentences — the over-defense stress test): "
        f"{stress['trigger_flagged']}/{stress['trigger_total']} flagged "
        f"(**FP rate {stress['trigger_rate']:.2%}**).\n"
        f"- Overall FP rate: **{stress['overall_rate']:.2%}**.\n"
        "- Why this is low: a lone rule/keyword match can never reach HIGH/block by "
        "itself (`core/severity.py`'s agreement gate requires the rule match to be "
        "corroborated by both elevated embedding similarity and classifier "
        "probability); the classifier's own decision threshold is chosen to keep "
        "precision >= 0.90 (`models/train.py::_select_threshold`) rather than "
        "maximizing recall unconditionally.\n"
    )

    lines.append("## 3. Latency\n")
    if latency:
        lines.append(
            f"- Average end-to-end detection time: **{float(latency['avg_latency_ms']):.2f} ms**.\n"
            f"- P50: {float(latency['p50_latency_ms']):.2f} ms, "
            f"P95: {float(latency['p95_latency_ms']):.2f} ms.\n"
            f"- Throughput: {float(latency['throughput_rps']):.2f} requests/sec "
            f"(single process, {latency['requests']} requests).\n"
            "- This is the full gateway decision (rules + SBERT embedding + classifier "
            "+ drift + severity), measured *before* any call to the downstream LLM — "
            "the LLM call only happens after the gateway has already decided "
            "pass/sanitize/block, so gateway latency is additive but small relative to "
            "typical LLM response times (hundreds of ms to seconds).\n"
        )
    else:
        lines.append(
            "- Run `python -m scripts.benchmark_latency` first — this writes "
            "`reports/latency_table.csv`.\n"
        )

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Build the consolidated evaluation report. By default "
                     "builds the FULL production semantic index and runs the "
                     "stress test over the full benign corpora -- pass --fast "
                     "for a quick smoke-test report instead."
    )
    parser.add_argument(
        "--sample-size", type=int, default=None,
        help="Cap the semantic index AND the stress-test prompt lists to "
             "at most this many rows. NOTE: results from a capped run are "
             "NOT representative of production -- use only for a quick check.",
    )
    parser.add_argument("--fast", action="store_true", help="Shortcut for --sample-size 2000.")
    return parser.parse_args()


def main():
    args = _parse_args()
    sample_size = args.sample_size if args.sample_size is not None else (2000 if args.fast else None)

    if sample_size:
        print(f"[eval] FAST mode: capping semantic index + stress test at {sample_size} rows. "
              f"Numbers in this report will NOT match production -- omit --fast/--sample-size "
              f"for the real evaluation report.\n", flush=True)
    else:
        print("[eval] Building the FULL production semantic index first "
              "(embeds the entire attack corpus -- watch [SemanticEngine] lines below).\n", flush=True)

    t0 = time.time()
    SemanticEngine.instance(max_attack_rows=sample_size, max_benign_rows=sample_size)
    print(f"[eval] semantic index ready in {time.time() - t0:.1f}s\n", flush=True)

    threshold = _load_threshold()
    latency = _load_latency()
    print("Running live stress test (benign.csv + trigger_benign.csv)...")
    stress = _run_stress_test(sample_size=sample_size)
    _write_report(threshold, latency, stress, fast_mode=bool(sample_size))
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()