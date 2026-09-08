"""
Generates the evaluation figures used in the paper / pitch deck:

  1. roc_curve.png                     - ROC curve with AUC
  2. pr_curve.png                      - Precision-Recall curve with AP
  3. confusion_matrix.png              - confusion matrix heatmap (tuned threshold)
  4. risk_score_distribution.png       - gateway risk-score histogram, benign vs attack
  5. category_recall_comparison.png    - prompt-injection vs harmful-content-request recall
  6. feature_importance.png            - Logistic Regression coefficient magnitudes
  7. pipeline_architecture.png         - gateway pipeline architecture diagram

Reuses models/train.py's dataset construction (train/test split is built
BEFORE the semantic index, so there's no leakage into these numbers) and
its class-weight selection, so the figures reflect the exact model that
`python -m models.train` would ship as detector.pkl.

Run with:  python -m scripts.generate_eval_figures   (from backend/)

Figures are written to backend/reports/figures/.
"""
import argparse
import os
import sys

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(BACKEND_DIR)
sys.path.insert(0, REPO_ROOT)

import matplotlib
matplotlib.use("Agg")  # headless — no display available in CI/hackathon box
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import confusion_matrix, precision_recall_curve, roc_curve, roc_auc_score, average_precision_score

import config
from core.classifier import FEATURE_NAMES
from core import severity
from models.train import (
    CLASS_WEIGHT_CANDIDATES,
    MIN_ACCEPTABLE_PRECISION,
    _category_breakdown,
    _fit_and_score,
    _select_threshold,
    build_dataset,
)

FIGURES_DIR = os.path.join(config.BASE_DIR, "reports", "figures")

# Match the dashboard's tier palette so the paper figures look consistent
# with the live demo.
_TIER_COLORS = {
    "benign": "#4ADE80",
    "attack": "#FF5C5C",
}
_CATEGORY_LABELS = {
    "prompt_injection": "Prompt injection\n(instruction override)",
    "harmful_content_request": "Harmful-content requests\n(supplementary evaluation)",
}


def _train_best_model(X_train, y_train, X_test, y_test):
    """Same class-weight comparison as models/train.py::main() — picks the
    candidate with the highest F1 at the default 0.5 threshold."""
    results = []
    for name, weight in CLASS_WEIGHT_CANDIDATES:
        model, probs, preds, precision, recall, f1 = _fit_and_score(weight, X_train, y_train, X_test, y_test)
        results.append((name, weight, model, probs, preds, f1))
    best_name, best_weight, model, probs, preds, _ = max(results, key=lambda r: r[5])
    return best_name, model, probs


def _plot_roc(y_test, probs, out_dir):
    fpr, tpr, _ = roc_curve(y_test, probs)
    auc = roc_auc_score(y_test, probs)

    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(fpr, tpr, color="#45D9C4", linewidth=2.2, label=f"ROC curve (AUC = {auc:.3f})")
    ax.plot([0, 1], [0, 1], color="#5C6878", linestyle="--", linewidth=1, label="Random classifier")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve — Layer C Classifier")
    ax.legend(loc="lower right")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.02)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "roc_curve.png"), dpi=200)
    plt.close(fig)
    return auc


def _plot_pr(y_test, probs, out_dir):
    precision, recall, _ = precision_recall_curve(y_test, probs)
    ap = average_precision_score(y_test, probs)

    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(recall, precision, color="#45D9C4", linewidth=2.2, label=f"PR curve (AP = {ap:.3f})")
    baseline = float(np.mean(y_test))
    ax.axhline(baseline, color="#5C6878", linestyle="--", linewidth=1, label=f"Baseline (attack rate = {baseline:.2f})")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curve — Layer C Classifier")
    ax.legend(loc="lower left")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.02)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "pr_curve.png"), dpi=200)
    plt.close(fig)
    return ap


def _plot_confusion_matrix(y_test, tuned_preds, threshold, out_dir):
    cm = confusion_matrix(y_test, tuned_preds, labels=[0, 1])

    fig, ax = plt.subplots(figsize=(5.5, 5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["benign", "attack"])
    ax.set_yticklabels(["benign", "attack"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"Confusion Matrix (tuned threshold = {threshold:.2f})")

    thresh = cm.max() / 2.0
    for i in range(2):
        for j in range(2):
            ax.text(
                j, i, format(cm[i, j], "d"),
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
                fontsize=14, fontweight="bold",
            )
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "confusion_matrix.png"), dpi=200)
    plt.close(fig)
    return cm


def _plot_risk_distribution(X_test, y_test, probs, out_dir):
    # Gateway risk score (Layer E fusion), not just the raw classifier
    # probability — this is what the dashboard/API actually reports per
    # request, so the paper figure should match it. X_test columns follow
    # core.classifier._extract_features' order: [rule_score, semantic_score, ...].
    risk_scores = np.array([
        severity.compute_risk_score(
            rule_score=float(feats[0]),
            embed_score=float(feats[1]),
            classifier_prob=float(prob),
            drift_score=0.0,  # single-shot evaluation, no session context
        )
        for feats, prob in zip(X_test, probs)
    ])

    benign_scores = risk_scores[y_test == 0]
    attack_scores = risk_scores[y_test == 1]

    fig, ax = plt.subplots(figsize=(7, 5))
    bins = np.linspace(0, 1, 26)
    ax.hist(benign_scores, bins=bins, alpha=0.58, label="Benign", color=_TIER_COLORS["benign"])
    ax.hist(attack_scores, bins=bins, alpha=0.58, label="Attack", color=_TIER_COLORS["attack"])
    ax.axvline(config.MEDIUM_SCORE_THRESHOLD, color="#F5B942", linestyle="--", linewidth=1.3, label="MEDIUM threshold")
    ax.axvline(config.LOW_SCORE_THRESHOLD, color="#7DD3FC", linestyle="--", linewidth=1.3, label="LOW threshold")
    ax.set_xlabel("Gateway risk score")
    ax.set_ylabel("Count")
    ax.set_title("Risk Score Distribution — Benign vs Attack (test set)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "risk_score_distribution.png"), dpi=200)
    plt.close(fig)
    return risk_scores


def _plot_feature_importance(model, out_dir):
    if not hasattr(model, "coef_"):
        print("Skipped feature_importance.png (model has no coefficients)")
        return

    coefs = model.coef_[0]
    order = np.argsort(np.abs(coefs))
    labels = [FEATURE_NAMES[i] for i in order]
    values = coefs[order]
    colors = ["#45D9C4" if v >= 0 else "#FF8A5C" for v in values]

    fig, ax = plt.subplots(figsize=(7, 5.2))
    ax.barh(labels, values, color=colors)
    ax.axvline(0, color="#5C6878", linewidth=1)
    ax.set_xlabel("Logistic Regression coefficient")
    ax.set_title("Feature Importance - Layer C Classifier")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "feature_importance.png"), dpi=200)
    plt.close(fig)


def _plot_pipeline_architecture(out_dir):
    stages = [
        "User Prompt",
        "Rule Engine",
        "Semantic Engine",
        "ML Classifier",
        "Risk Fusion",
        "Explainability",
        "Pass / Sanitize / Block",
    ]

    fig, ax = plt.subplots(figsize=(7.5, 8.5))
    ax.axis("off")
    y_positions = np.linspace(0.92, 0.10, len(stages))

    for idx, (stage, y) in enumerate(zip(stages, y_positions)):
        ax.text(
            0.5, y, stage,
            ha="center", va="center",
            fontsize=12,
            fontweight="bold" if idx in (0, len(stages) - 1) else "normal",
            bbox={
                "boxstyle": "round,pad=0.45,rounding_size=0.06",
                "facecolor": "#101B2D" if idx not in (0, len(stages) - 1) else "#163B3A",
                "edgecolor": "#45D9C4",
                "linewidth": 1.5,
            },
            color="#F8FAFC",
        )
        if idx < len(stages) - 1:
            ax.annotate(
                "",
                xy=(0.5, y_positions[idx + 1] + 0.045),
                xytext=(0.5, y - 0.045),
                arrowprops={"arrowstyle": "->", "color": "#45D9C4", "linewidth": 1.8},
            )

    ax.set_title(
        "Prompt Injection Detection Gateway",
        fontsize=15,
        fontweight="bold",
        color="#F8FAFC",
        pad=18,
    )
    fig.patch.set_facecolor("#0B1220")
    ax.set_facecolor("#0B1220")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "pipeline_architecture.png"), dpi=200, facecolor=fig.get_facecolor())
    plt.close(fig)


def _plot_category_recall(category_stats, out_dir):
    cats = [c for c in ("prompt_injection", "harmful_content_request") if c in category_stats and category_stats[c]["total"]]
    recalls = [category_stats[c]["caught"] / category_stats[c]["total"] for c in cats]
    labels = [_CATEGORY_LABELS.get(c, c) for c in cats]
    ns = [category_stats[c]["total"] for c in cats]

    fig, ax = plt.subplots(figsize=(6.5, 5))
    bars = ax.bar(labels, recalls, color=["#45D9C4", "#F5B942"][: len(cats)], width=0.5)
    for bar, recall, n in zip(bars, recalls, ns):
        ax.text(bar.get_x() + bar.get_width() / 2, recall + 0.02, f"{recall * 100:.1f}%\n(n={n})",
                ha="center", va="bottom", fontsize=10)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Recall")
    ax.set_title("Attack Recall by Category (tuned threshold)")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "category_recall_comparison.png"), dpi=200)
    plt.close(fig)


_DEFAULT_FAST_SAMPLE_SIZE = 2000


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Generate evaluation figures. Runs in FAST mode "
                     f"(sample_size={_DEFAULT_FAST_SAMPLE_SIZE}) by default so it "
                     "finishes in seconds -- pass --full for the real, full-corpus "
                     "figures (this embeds ~295k rows and is slow on CPU)."
    )
    parser.add_argument("--sample-size", type=int, default=None,
                         help="Downsample attacks.csv/benign.csv (stratified) before training, same as models/train.py. "
                              "Overrides the fast-mode default.")
    parser.add_argument("--fast", action="store_true",
                         help=f"Explicit alias for the default fast mode (sample_size={_DEFAULT_FAST_SAMPLE_SIZE}).")
    parser.add_argument("--full", action="store_true",
                         help="Use the full corpus, no downsampling (slow -- this is what used to be the default).")
    return parser.parse_args()


def main():
    args = _parse_args()
    if args.sample_size is not None:
        sample_size = args.sample_size
    elif args.full:
        sample_size = None
    else:
        # Fast mode is now the default -- pass --full for the real figures.
        sample_size = _DEFAULT_FAST_SAMPLE_SIZE

    if sample_size:
        print(f"FAST mode (default): sample_size={sample_size} -- figures will be based on a "
              f"downsampled corpus, not the full production one. Pass --full for real figures.\n")
    else:
        print("FULL mode: using the entire corpus -- this will embed ~295k rows and can take "
              "a long time on CPU.\n")

    os.makedirs(FIGURES_DIR, exist_ok=True)

    print("Building train/test split (leakage-safe, mirrors models/train.py)...")
    X_train, y_train, X_test, y_test, test_texts, test_clusters = build_dataset(sample_size=sample_size)

    if len(set(y_test)) != 2:
        print("Test set does not contain both classes — cannot generate ROC/PR/confusion "
              "figures meaningfully. Add more rows to data/attacks.csv or data/benign.csv.")
        return

    print("Fitting classifier (comparing class weights, same as models/train.py)...")
    best_name, model, probs = _train_best_model(X_train, y_train, X_test, y_test)
    print(f"Selected class_weight setting: {best_name}")

    threshold, precision, recall, reason = _select_threshold(y_test, probs, MIN_ACCEPTABLE_PRECISION)
    tuned_preds = (probs >= threshold).astype(int)
    print(f"Tuned threshold: {threshold:.3f} ({reason})")

    auc = _plot_roc(y_test, probs, FIGURES_DIR)
    print(f"Saved roc_curve.png (AUC={auc:.4f})")

    ap = _plot_pr(y_test, probs, FIGURES_DIR)
    print(f"Saved pr_curve.png (AP={ap:.4f})")

    _plot_confusion_matrix(y_test, tuned_preds, threshold, FIGURES_DIR)
    print("Saved confusion_matrix.png")

    _plot_risk_distribution(X_test, y_test, probs, FIGURES_DIR)
    print("Saved risk_score_distribution.png")

    _plot_feature_importance(model, FIGURES_DIR)
    print("Saved feature_importance.png")

    _plot_pipeline_architecture(FIGURES_DIR)
    print("Saved pipeline_architecture.png")

    category_stats = _category_breakdown(y_test, tuned_preds, test_clusters)
    _plot_category_recall(category_stats, FIGURES_DIR)
    print("Saved category_recall_comparison.png")

    print(f"\nAll figures written to {FIGURES_DIR}")


if __name__ == "__main__":
    main()