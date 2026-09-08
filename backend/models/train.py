"""
Trains the Layer C classifier (Logistic Regression) from the attack and
benign corpora and persists it to models/detector.pkl.

Run with:  python -m models.train   (from backend/)

IMPORTANT (leakage fix): the semantic-similarity feature is computed by
searching a FAISS index built from the attack/benign corpora. If that
index is built from the FULL corpus before splitting, every "test" row
is compared against an index that already contains itself -- inflating
attack_similarity to ~1.0 for every attack row and making the reported
accuracy meaningless. To avoid this, we split each corpus into
train/test FIRST, then build the semantic index from the TRAIN rows
only (via SemanticEngine.for_training), and use that same train-only
index to featurize both the train and test rows.
"""
import argparse
import json
import os
import sys
from collections import Counter

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(BACKEND_DIR)
sys.path.insert(0, REPO_ROOT)

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
    precision_recall_curve,
    f1_score,
)

import config
from core.classifier import _extract_features
from core.rule_engine import match_rules
from core.semantic_engine import SemanticEngine

TEST_SIZE = 0.25
RANDOM_STATE = 42

# Candidate class weightings to compare (recommendation #2: weight the
# attack class more heavily than plain "balanced" so recall improves).
# "balanced" reweights inversely proportional to class frequency; the
# explicit dicts push further in the attack-recall direction on top of
# that, at the cost of some benign precision -- exactly the trade-off the
# review flagged.
CLASS_WEIGHT_CANDIDATES = [
    ("balanced", "balanced"),
    ("1.5x attack", {0: 1.0, 1: 1.5}),
    ("2x attack", {0: 1.0, 1: 2.0}),
    ("3x attack", {0: 1.0, 1: 3.0}),
]

# Precision floor for the "recall-optimal" threshold pick (recommendation
# #1 + #3): among thresholds that keep benign precision at or above this,
# choose the one with the highest recall. This keeps the false-positive
# rate bounded instead of chasing recall unconditionally.
MIN_ACCEPTABLE_PRECISION = 0.90

# ---------------------------------------------------------------------------
# Attack-category taxonomy (review feedback: attacks.csv mixes genuine
# instruction-override / prompt-injection phrasing (HackAPrompt levels,
# Developer Mode Jailbreak, Instruction Override, Persona Hijack, System
# Prompt Leak, Safety Bypass, Credential Exfiltration) with JBB-Behaviors
# rows, which are harmful-CONTENT requests ("write malware", "explain
# identity theft") rather than attempts to override the model's
# instructions. Both are adversarial and both belong in the training set,
# but reporting a single blended accuracy/recall number overstates what
# "prompt injection detection" means. These maps let evaluation report
# recall separately per category instead of hiding the split.
# ---------------------------------------------------------------------------
PROMPT_INJECTION_CLUSTERS = {
    "Developer Mode Jailbreak",
    "Instruction Override",
    "Persona Hijack",
    "System Prompt Leak",
    "Safety Bypass",
    "Credential Exfiltration",
}
HARMFUL_CONTENT_CLUSTERS = {
    "Harassment/Discrimination",
    "Malware/Hacking",
    "Physical harm",
    "Economic harm",
    "Fraud/Deception",
    "Disinformation",
    "Sexual/Adult content",
    "Privacy",
    "Expert advice",
    "Government decision-making",
}


def _categorize(cluster_name):
    """Maps a raw cluster_name onto the broader evaluation category it
    belongs to, so metrics can be reported per-category instead of only
    as one blended "attack" number."""
    if not cluster_name:
        return "unlabeled"
    name = str(cluster_name)
    if name.startswith("HackAPrompt") or name in PROMPT_INJECTION_CLUSTERS:
        return "prompt_injection"
    if name in HARMFUL_CONTENT_CLUSTERS:
        return "harmful_content_request"
    if name in ("benign.csv", "trigger_benign.csv"):
        return "benign"
    return "unlabeled"


def _load_column(path: str, col: str = "text"):
    if not os.path.exists(path):
        return []
    return pd.read_csv(path)[col].astype(str).tolist()


def _stratified_sample_df(df, group_col, n, random_state=RANDOM_STATE):
    """Downsamples a dataframe to at most n rows, spread proportionally
    across group_col so small-but-important groups (e.g. the 10-row
    harmful-content clusters buried inside 393k HackAPrompt rows) don't
    get wiped out by a plain df.sample(n). Every group keeps at least 1
    row (capped at its own size) if the group exists at all."""
    if len(df) <= n:
        return df
    groups = df.groupby(group_col, dropna=False)
    n_groups = len(groups)
    # proportional share, but never less than 1 row per group
    per_group = max(1, n // max(n_groups, 1))
    sampled = groups.apply(
        lambda g: g.sample(n=min(per_group, len(g)), random_state=random_state)
    ).reset_index(drop=True)
    # if proportional allocation undershoots n (small groups capped),
    # top up randomly from whatever wasn't picked yet
    if len(sampled) < n:
        remaining = df.drop(sampled.index, errors="ignore")
        top_up = remaining.sample(
            n=min(n - len(sampled), len(remaining)), random_state=random_state
        )
        sampled = pd.concat([sampled, top_up], ignore_index=True)
    return sampled.sample(frac=1, random_state=random_state).reset_index(drop=True)


def _sample_list(items, n, random_state=RANDOM_STATE):
    if len(items) <= n:
        return items
    rng = np.random.RandomState(random_state)
    idx = rng.choice(len(items), size=n, replace=False)
    return [items[i] for i in idx]


def _split(texts, clusters=None):
    """Splits texts (and optional parallel cluster labels) into
    train/test. Returns (train_texts, test_texts) or, if clusters is
    given, (train_texts, train_clusters, test_texts, test_clusters)."""
    if len(texts) < 2:
        # Too small to split meaningfully -- treat everything as train
        # and leave test empty for this corpus.
        if clusters is not None:
            return texts, clusters, [], []
        return texts, []

    idx = list(range(len(texts)))
    train_idx, test_idx = train_test_split(idx, test_size=TEST_SIZE, random_state=RANDOM_STATE)

    train_texts = [texts[i] for i in train_idx]
    test_texts = [texts[i] for i in test_idx]

    if clusters is not None:
        train_clusters = [clusters[i] for i in train_idx]
        test_clusters = [clusters[i] for i in test_idx]
        return train_texts, train_clusters, test_texts, test_clusters

    return train_texts, test_texts


def _featurize(texts, label, semantic_engine, clusters=None):
    """Returns (X, y, texts_out, clusters_out). clusters_out mirrors texts
    1:1 (defaulting to None per row when no cluster labels were supplied),
    kept so false negatives can be traced back to source text + cluster
    for inspection (recommendation #4).

    Uses analyze_batch() (one batched SBERT call) instead of calling
    analyze() per row -- with large corpora (e.g. the full HackAPrompt
    dataset merged into attacks.csv), one-at-a-time encoding is the
    dominant cost and can turn a few-minute run into a multi-hour one.
    """
    clusters = clusters if clusters is not None else [None] * len(texts)
    texts = list(texts)
    clusters = list(clusters)

    rule_scores = [match_rules(text).score for text in texts]
    semantics = semantic_engine.analyze_batch(texts)

    X = [
        _extract_features(text, rule_score, semantic.context_anchored_score, 0.0)
        for text, rule_score, semantic in zip(texts, rule_scores, semantics)
    ]
    y = [label] * len(texts)
    return X, y, texts, clusters


def build_dataset(sample_size=None):
    """sample_size: if set, downsamples the attack corpus (stratified by
    cluster_name so the tiny harmful-content clusters survive) and the
    benign corpus to roughly this many rows each BEFORE any featurizing
    or SBERT encoding happens. attacks.csv alone is ~393k rows, so
    embedding it in full is what makes a run take a long time -- pass
    --fast or --sample-size N for a quick smoke-test run."""
    attacks_df = pd.read_csv(config.ATTACK_CORPUS_PATH, low_memory=False)
    if sample_size:
        attacks_df = _stratified_sample_df(attacks_df, "cluster_name", sample_size)
    attacks = attacks_df["text"].astype(str).tolist()
    attack_clusters = (
        attacks_df["cluster_name"].astype(str).tolist()
        if "cluster_name" in attacks_df.columns else [None] * len(attacks)
    )
    benign = _load_column(config.BENIGN_CORPUS_PATH)
    if sample_size:
        benign = _sample_list(benign, sample_size)
    benign_trigger = _load_column(config.TRIGGER_BENIGN_CORPUS_PATH)

    # Split every corpus BEFORE any embedding/indexing happens.
    train_attacks, train_clusters, test_attacks, test_attack_clusters = _split(attacks, attack_clusters)
    train_benign, test_benign = _split(benign)
    train_trigger, test_trigger = _split(benign_trigger)

    # Semantic engine indexed ONLY on the training rows -- test rows are
    # never added to the index, so they can never match themselves.
    semantic_engine = SemanticEngine.for_training(
        attack_texts=train_attacks,
        attack_clusters=train_clusters,
        benign_texts=train_trigger,
    )

    X_train, y_train = [], []
    X_test, y_test, test_texts, test_clusters = [], [], [], []

    for texts, label, clusters in [
        (train_attacks, 1, train_clusters),
        (train_benign, 0, None),
        (train_trigger, 0, None),
    ]:
        xs, ys, _, _ = _featurize(texts, label, semantic_engine, clusters)
        X_train += xs
        y_train += ys

    for texts, label, clusters, source in [
        (test_attacks, 1, test_attack_clusters, "attacks.csv"),
        (test_benign, 0, None, "benign.csv"),
        (test_trigger, 0, None, "trigger_benign.csv"),
    ]:
        clusters = clusters if clusters is not None else [source] * len(texts)
        xs, ys, txt, clu = _featurize(texts, label, semantic_engine, clusters)
        X_test += xs
        y_test += ys
        test_texts += txt
        test_clusters += clu

    return (
        np.array(X_train), np.array(y_train),
        np.array(X_test), np.array(y_test),
        test_texts, test_clusters,
    )


def _metrics_at_threshold(y_true, probs, threshold):
    preds = (probs >= threshold).astype(int)
    tp = int(np.sum((preds == 1) & (y_true == 1)))
    fp = int(np.sum((preds == 1) & (y_true == 0)))
    fn = int(np.sum((preds == 0) & (y_true == 1)))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def _print_threshold_sweep(y_test, probs):
    """Recommendation #1 + #3: instead of only reporting the default 0.5
    cutoff, sweep thresholds and show the precision/recall/F1 trade-off so
    the right operating point can be picked deliberately."""
    print("\nThreshold sweep (benign=negative, attack=positive):")
    print(f"{'threshold':>10} {'precision':>10} {'recall':>10} {'f1':>8}")
    for t in np.arange(0.30, 0.71, 0.05):
        p, r, f1 = _metrics_at_threshold(y_test, probs, t)
        print(f"{t:>10.2f} {p:>10.3f} {r:>10.3f} {f1:>8.3f}")


def _select_threshold(y_test, probs, min_precision=MIN_ACCEPTABLE_PRECISION):
    """Picks the classifier's own decision threshold: the highest-recall
    point on the PR curve that still keeps precision >= min_precision. If
    no threshold clears that precision bar (small/noisy test sets), falls
    back to the F1-maximizing threshold instead of silently returning
    nothing useful."""
    precisions, recalls, thresholds = precision_recall_curve(y_test, probs)
    # precision_recall_curve returns len(thresholds) == len(precisions) - 1
    precisions, recalls = precisions[:-1], recalls[:-1]

    eligible = [i for i in range(len(thresholds)) if precisions[i] >= min_precision]
    if eligible:
        best_i = max(eligible, key=lambda i: recalls[i])
        reason = f"highest recall with precision >= {min_precision:.2f}"
    else:
        f1s = [
            2 * precisions[i] * recalls[i] / (precisions[i] + recalls[i])
            if (precisions[i] + recalls[i]) else 0.0
            for i in range(len(thresholds))
        ]
        best_i = int(np.argmax(f1s))
        reason = f"no threshold reached precision >= {min_precision:.2f}; used max-F1 instead"

    return float(thresholds[best_i]), float(precisions[best_i]), float(recalls[best_i]), reason


def _inspect_false_negatives(y_test, preds, test_texts, test_clusters, limit=15):
    """Recommendation #4: surface which attacks are being missed so the
    next data/feature-engineering pass has something concrete to target,
    instead of only knowing the aggregate recall number."""
    fn_idx = [i for i in range(len(y_test)) if y_test[i] == 1 and preds[i] == 0]
    print(f"\nFalse negatives (attacks classified as benign): {len(fn_idx)}")
    if not fn_idx:
        return

    cluster_counts = Counter(test_clusters[i] for i in fn_idx)
    print("By cluster (helps spot whether misses concentrate in one attack family):")
    for cluster, count in cluster_counts.most_common():
        print(f"  {cluster or 'unlabeled'}: {count}")

    category_counts = Counter(_categorize(test_clusters[i]) for i in fn_idx)
    print("By category (prompt_injection vs harmful_content_request -- see review note above):")
    for category, count in category_counts.most_common():
        print(f"  {category}: {count}")

    print(f"\nSample missed attacks (up to {limit}):")
    for i in fn_idx[:limit]:
        text = test_texts[i]
        preview = text if len(text) <= 100 else text[:97] + "..."
        print(f"  [{_categorize(test_clusters[i])} / {test_clusters[i] or 'unlabeled'}] {preview}")


def _category_breakdown(y_test, preds, test_clusters):
    """Reports recall separately for prompt-injection-phrasing rows vs
    harmful-content-request rows within the attack class, addressing the
    review's core critique: a single blended attack-recall number implies
    the detector was evaluated on one coherent attack type when the
    dataset actually spans two related-but-distinct categories."""
    categories = {}
    for i in range(len(y_test)):
        if y_test[i] != 1:
            continue  # breakdown only applies to the attack class
        cat = _categorize(test_clusters[i])
        categories.setdefault(cat, {"total": 0, "caught": 0})
        categories[cat]["total"] += 1
        if preds[i] == 1:
            categories[cat]["caught"] += 1

    print("\nAttack recall by category (tuned threshold):")
    print(f"{'category':<26} {'n':>6} {'recall':>8}")
    for cat, stats in sorted(categories.items(), key=lambda kv: -kv[1]["total"]):
        recall = stats["caught"] / stats["total"] if stats["total"] else 0.0
        print(f"{cat:<26} {stats['total']:>6} {recall:>8.3f}")
    print(
        "Note: 'harmful_content_request' rows (JBB-Behaviors) test whether the\n"
        "gateway also flags harmful-content asks; they are not instruction-\n"
        "override attempts, so don't cite this recall number as \"prompt\n"
        "injection detection accuracy\" without noting the split above."
    )
    return categories


def _fit_and_score(class_weight, X_train, y_train, X_test, y_test):
    model = LogisticRegression(max_iter=1000, class_weight=class_weight)
    model.fit(X_train, y_train)
    probs = model.predict_proba(X_test)[:, 1]
    preds = model.predict(X_test)
    precision, recall, f1 = _metrics_at_threshold(y_test, probs, 0.5)
    return model, probs, preds, precision, recall, f1


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Train the Layer C classifier. By default uses the full "
                     "corpus (~393k attack rows) -- pass --fast or "
                     "--sample-size for a quick run."
    )
    parser.add_argument(
        "--sample-size", type=int, default=None,
        help="Downsample attacks.csv and benign.csv to at most this many "
             "rows each (stratified by attack cluster) before training.",
    )
    parser.add_argument(
        "--fast", action="store_true",
        help="Shortcut for --sample-size 2000, just to sanity-check the "
             "pipeline end-to-end quickly.",
    )
    return parser.parse_args()


def main():
    args = _parse_args()
    sample_size = args.sample_size if args.sample_size is not None else (2000 if args.fast else None)
    if sample_size:
        print(f"Running in fast/downsampled mode: sample_size={sample_size} "
              f"(stratified by attack cluster). Omit --fast/--sample-size for a full run.\n")

    X_train, y_train, X_test, y_test, test_texts, test_clusters = build_dataset(sample_size=sample_size)

    train_counts = Counter(y_train)
    test_counts = Counter(y_test)
    print(
        f"Train class counts -- benign: {train_counts[0]}, attack: {train_counts[1]}  "
        f"(attack:benign ratio {train_counts[1] / max(train_counts[0], 1):.1f}:1)"
    )
    print(f"Test class counts  -- benign: {test_counts[0]}, attack: {test_counts[1]}")
    print(f"Train rows: {len(y_train)} | Test rows (held out, never indexed): {len(y_test)}")

    # Recommendation #2: compare class-weight settings at the default 0.5
    # cutoff before picking one, rather than assuming "balanced" is best.
    print("\nClass-weight comparison (at default 0.5 threshold):")
    print(f"{'weighting':>14} {'precision':>10} {'recall':>10} {'f1':>8}")
    results = []
    for name, weight in CLASS_WEIGHT_CANDIDATES:
        model, probs, preds, precision, recall, f1 = _fit_and_score(weight, X_train, y_train, X_test, y_test)
        print(f"{name:>14} {precision:>10.3f} {recall:>10.3f} {f1:>8.3f}")
        results.append((name, weight, model, probs, preds, f1))

    best_name, best_weight, model, probs, preds, _ = max(results, key=lambda r: r[5])
    print(f"\nSelected class_weight={best_weight!r} ({best_name}) -- highest F1 at default threshold.")

    print(f"\nClassification report @ 0.5 threshold, class_weight={best_weight!r}:")
    print(classification_report(y_test, preds, target_names=["benign", "attack"], zero_division=0))

    cm = confusion_matrix(y_test, preds, labels=[0, 1])
    print("Confusion matrix (rows = actual, cols = predicted) [benign, attack]:")
    print(cm)

    # Threshold-independent metrics -- more informative than accuracy on
    # an imbalanced dataset, since they summarize performance across all
    # possible decision thresholds rather than just the default 0.5 cutoff.
    if len(set(y_test)) == 2:
        roc_auc = roc_auc_score(y_test, probs)
        pr_auc = average_precision_score(y_test, probs)
        print(f"ROC-AUC: {roc_auc:.4f}")
        print(f"PR-AUC (average precision): {pr_auc:.4f}")
    else:
        roc_auc = pr_auc = None
        print("ROC-AUC / PR-AUC skipped: test set only contains one class.")

    # Recommendation #1 + #3: sweep thresholds, then pick the recall-optimal
    # one (precision floor MIN_ACCEPTABLE_PRECISION) instead of shipping the
    # default 0.5 cutoff.
    _print_threshold_sweep(y_test, probs)
    best_threshold, best_precision, best_recall, reason = _select_threshold(y_test, probs)
    best_f1 = 2 * best_precision * best_recall / (best_precision + best_recall) if (best_precision + best_recall) else 0.0
    print(
        f"\nRecall-optimal threshold: {best_threshold:.3f} "
        f"(precision={best_precision:.3f}, recall={best_recall:.3f}, f1={best_f1:.3f}) -- {reason}"
    )

    tuned_preds = (probs >= best_threshold).astype(int)
    print(f"\nClassification report @ tuned threshold {best_threshold:.3f}:")
    print(classification_report(y_test, tuned_preds, target_names=["benign", "attack"], zero_division=0))
    tuned_cm = confusion_matrix(y_test, tuned_preds, labels=[0, 1])
    print("Confusion matrix @ tuned threshold [benign, attack]:")
    print(tuned_cm)

    # Recommendation #4: inspect what's still being missed at the tuned
    # threshold, using the ORIGINAL 0.5-threshold predictions is less
    # useful here -- use the tuned predictions since that's what ships.
    _inspect_false_negatives(y_test, tuned_preds, test_texts, test_clusters)

    # Review feedback: report attack recall split by category
    # (prompt_injection vs harmful_content_request) instead of only the
    # single blended number above -- see PROMPT_INJECTION_CLUSTERS /
    # HARMFUL_CONTENT_CLUSTERS at the top of this file.
    category_stats = _category_breakdown(y_test, tuned_preds, test_clusters)

    if roc_auc is not None:
        print("\nFor an IEEE paper (recall-optimal operating point):")
        print(f"{'Metric':<12}{'Value':>10}")
        print(f"{'Precision':<12}{best_precision * 100:>9.1f}%")
        print(f"{'Recall':<12}{best_recall * 100:>9.1f}%")
        print(f"{'F1-score':<12}{best_f1 * 100:>9.1f}%")
        print(f"{'ROC-AUC':<12}{roc_auc * 100:>9.2f}%")
        print(f"{'PR-AUC':<12}{pr_auc * 100:>9.2f}%")

    os.makedirs(config.MODEL_DIR, exist_ok=True)
    out_path = os.path.join(config.MODEL_DIR, "detector.pkl")
    joblib.dump(model, out_path)
    print(f"\nSaved trained classifier ({best_name}) to {out_path}")

    # Persist the tuned threshold so config.py can pick it up at runtime
    # (see config.py's _THRESHOLD_FILE loading block) without anyone
    # having to hand-edit MEDIUM_CLASSIFIER_THRESHOLD after every retrain.
    # HIGH stays a fixed +0.20 margin above MEDIUM so the HIGH tier still
    # demands a meaningfully more confident prediction, capped at 0.95.
    threshold_path = os.path.join(config.MODEL_DIR, "threshold.json")
    with open(threshold_path, "w") as f:
        json.dump({
            "medium_classifier_threshold": round(best_threshold, 4),
            "high_classifier_threshold": round(min(best_threshold + 0.20, 0.95), 4),
            "precision_at_threshold": round(best_precision, 4),
            "recall_at_threshold": round(best_recall, 4),
            "class_weight": best_name,
            # Review feedback: keep the category split alongside the
            # headline numbers so anyone reading this file later (e.g.
            # while writing up results) sees the blended recall was never
            # measured on prompt-injection phrasing alone.
            "recall_by_category": {
                cat: round(stats["caught"] / stats["total"], 4) if stats["total"] else None
                for cat, stats in category_stats.items()
            },
        }, f, indent=2)
    print(f"Saved tuned threshold to {threshold_path} (config.py will pick this up automatically)")


if __name__ == "__main__":
    main()