"""
Central configuration for the Prompt Injection Detection Gateway.
All tunable thresholds live here so they can be calibrated in one place
(see PRD Section 5.4 / 9 - false positive calibration).
"""
import os


def _load_dotenv(path: str) -> None:
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_load_dotenv(os.path.join(BASE_DIR, ".env"))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(BASE_DIR, "database", "gateway.db")
MODEL_DIR = os.path.join(BASE_DIR, "models")

ATTACK_CORPUS_PATH = os.path.join(DATA_DIR, "attacks.csv")
BENIGN_CORPUS_PATH = os.path.join(DATA_DIR, "benign.csv")
TRIGGER_BENIGN_CORPUS_PATH = os.path.join(DATA_DIR, "trigger_benign.csv")

# ---------------------------------------------------------------------------
# Embedding model
# ---------------------------------------------------------------------------
EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIM = 384

# ---------------------------------------------------------------------------
# Layer weights (risk score combination — PRD 5.4)
# ---------------------------------------------------------------------------
WEIGHT_RULE = 0.25
WEIGHT_EMBEDDING = 0.30
WEIGHT_CLASSIFIER = 0.30
WEIGHT_DRIFT = 0.15

# ---------------------------------------------------------------------------
# Tier thresholds
# ---------------------------------------------------------------------------
HIGH_EMBED_THRESHOLD = 0.70
HIGH_CLASSIFIER_THRESHOLD = 0.70

MEDIUM_SCORE_THRESHOLD = 0.55
LOW_SCORE_THRESHOLD = 0.25

MEDIUM_EMBED_THRESHOLD = 0.50
MEDIUM_CLASSIFIER_THRESHOLD = 0.50

# ---------------------------------------------------------------------------
# Classifier decision threshold (auto-calibrated)
# ---------------------------------------------------------------------------
# models/train.py sweeps the precision-recall curve on the held-out test
# split and writes the recall-optimal cutoff to models/threshold.json (see
# train.py::_select_threshold). If that file exists we use it to override
# MEDIUM_CLASSIFIER_THRESHOLD / HIGH_CLASSIFIER_THRESHOLD above, so a
# retrain automatically recalibrates how much weight a given classifier
# probability carries in severity.get_tier() -- without editing this file
# by hand. Falls back to the static defaults above if train.py hasn't been
# run yet (or the file is missing/corrupt).
_THRESHOLD_FILE = os.path.join(MODEL_DIR, "threshold.json")
if os.path.exists(_THRESHOLD_FILE):
    try:
        import json as _json
        with open(_THRESHOLD_FILE) as _f:
            _tuned = _json.load(_f)
        # The tuned cutoff replaces MEDIUM_CLASSIFIER_THRESHOLD (the "is this
        # classifier probability elevated enough to matter" gate). HIGH stays
        # a fixed margin above it so the HIGH tier still requires a
        # meaningfully more confident prediction than MEDIUM.
        MEDIUM_CLASSIFIER_THRESHOLD = float(_tuned["medium_classifier_threshold"])
        HIGH_CLASSIFIER_THRESHOLD = float(_tuned["high_classifier_threshold"])
    except Exception:
        pass  # keep static defaults if the file is missing a key or malformed

# Stricter thresholds applied to tool_output (indirect injection — Layer F)
TOOL_OUTPUT_EMBED_DELTA = -0.10       # subtract from HIGH threshold, i.e. easier to trigger
TOOL_OUTPUT_CLASSIFIER_DELTA = -0.10

# ---------------------------------------------------------------------------
# Multi-turn drift (Layer D)
# ---------------------------------------------------------------------------
DRIFT_WINDOW = 5                # last N turns considered
DRIFT_ALERT_THRESHOLD = 0.45    # cosine distance from session-intent(0)

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
CORS_ORIGINS = ["http://localhost:5173", "http://localhost:3000"]

# ---------------------------------------------------------------------------
# Downstream LLM provider
# ---------------------------------------------------------------------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
LLM_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "45"))
