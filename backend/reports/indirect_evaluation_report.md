# Aegis — Indirect Injection Evaluation Report

Corpora: `data/indirect_injection.csv` (N=60 attack rows) vs `data/indirect_benign.csv` (N=46 benign rows). All rows are evaluation-only — not part of classifier training data and not included in the direct-injection evaluation corpora.

## 1. Effect of Window Scoring on Recall

| Metric | WITH windowing | WITHOUT windowing | Delta |
|---|---|---|---|
| Precision | 0.977 | 1.000 | -0.023 |
| Recall    | 0.700 | 0.033 | +0.667 |
| F1        | 0.816 | 0.065 | +0.751 |
| FPR (benign) | 2.2% | 0.0% | +2.2% |


Window scoring improves recall by 66.7% on this corpus. This confirms that SBERT dilution was happening when scoring long documents as single vectors — the windowing fix is materially effective.


## 2. TOOL_OUTPUT_EMBED_DELTA Calibration (Confirmation #1)

The current `TOOL_OUTPUT_EMBED_DELTA = -0.10` makes the HIGH-tier embed threshold stricter for tool_output inputs. Under max-window scoring, the observed FPR on `indirect_benign.csv` is **2.2%** (N=46).


The delta produces a low but non-zero FPR on boundary-adversarial input (1/46 = 2.2% (95% CI: 0.4%–11.3%)) — this is a more credible number than the earlier 0.0% and shows no sign of gross miscalibration, but should not be read as proof of correct tuning.


## 3. False-Positive Rate by Benign Subset

These subsets are specifically adversarial to the new rule patterns:


| Subset | Flagged / Total | FPR (95% Wilson CI) | Tests |
|---|---|---|---|

| Legitimate base64 content (JWTs, data URIs, IDs) | 0/11 | 0.0% (95% CI: 0.0%–25.9%) | `indirect_delimiter_inject`, `indirect_split_chunk` |

| Legitimate [System]/[Admin]/`<Section>` headers | 1/18 | 5.6% (95% CI: 1.0%–25.8%) | `indirect_delimiter_inject`, `indirect_split_chunk` |

| Clean long documents (emails, papers, reviews) | 0/17 | 0.0% (95% CI: 0.0%–18.4%) | `indirect_delimiter_inject`, `indirect_split_chunk` |



*Note on the single flagged delimiter row:* The only false positive across all 46 benign rows is Row 39 (`"<Instructions>: Please follow standard laboratory PPE protocols..."`), which triggered `indirect_delimiter_inject` due to the exact colon-terminated tag syntax `<Instructions>:`. The earlier `[System]: All services restarted...` log matched the pattern but was safely suppressed to LOW/pass by the agreement gate, and the newly added `indirect_terse_directive` rule caused zero false positives across the entire benign corpus.


## 4. Recall by Scenario Type (WITH windowing)

> **⚠️ SAMPLE-SIZE CAVEAT (N≈11–13 per scenario):** Each scenario type contains 11–13 examples. Recall estimates at this sample size have wide confidence intervals (reported below via 95% Wilson score intervals, spanning up to 49 pp). These figures show *which scenario types the pipeline handles well or poorly*, not a stable quantitative estimate. Do not compare these numbers to the N=393k direct-injection metrics.


| Scenario type | Detected / N | Recall (95% Wilson CI) |
|---|---|---|

| malicious_email | 7/12 | 58.3% (95% CI: 32.0%–80.7%) |

| obfuscated | 9/11 | 81.8% (95% CI: 52.3%–94.9%) |

| poisoned_rag | 11/13 | 84.6% (95% CI: 57.8%–95.7%) |

| poisoned_webpage | 9/12 | 75.0% (95% CI: 46.8%–91.1%) |

| structured_data | 6/12 | 50.0% (95% CI: 25.4%–74.6%) |



## 5. Recall by Document Length Bucket (WITH windowing)

| Length bucket | Detected / N | Recall (95% Wilson CI) | Note |
|---|---|---|---|

| short | 24/37 | 64.9% (95% CI: 48.8%–78.2%) |  |

| medium | 8/13 | 61.5% (95% CI: 35.5%–82.3%) |  |

| long | 10/10 | 100.0% (95% CI: 72.2%–100.0%) | 10/10 (100.0%, 95% CI: 72.2%–100.0%) on the long-document bucket — directionally strong and validates the windowing fix on the exact condition it was built for, but N=10 is a small sample; treat as promising, not conclusive. |



## 6. Honest Comparison to Direct-Injection Performance

The direct-injection classifier achieves **98.4% recall** on the held-out test split (N≈393k rows, trained on real attack data). Indirect recall stands at **70.0%** vs. **98.4%** direct (28.4 pp gap remaining) — windowing was the single biggest lever, raising recall from 3.3% to 70.0% (+66.7 pp), starting from near-zero.

**Sample-size caveat (overall N=60):** Precision and recall estimates at this sample size have wide confidence intervals (overall recall: 42/60 (70.0%, 95% CI: 57.5%–80.1%); overall benign FPR: 1/46 (2.2%, 95% CI: 0.4%–11.3%)). The numbers demonstrate the pipeline's behaviour on realistic indirect injection examples hand-curated to cover five distinct scenarios. They cannot be compared directly to the direct-injection metrics derived from a 393k-row corpus. A production-grade indirect injection evaluation would require a substantially larger labelled corpus of real retrieved-document attacks. Do not cite these numbers as equivalent to the direct-injection recall figure.
