"""
SBERT embedding wrapper. Wraps sentence-transformers so the rest of the
codebase never touches the model directly (makes it trivial to swap the
backbone later, e.g. to a fine-tuned in-domain model).
"""
import time

import numpy as np

try:
    from sentence_transformers import SentenceTransformer
    _HAS_ST = True
except ImportError:
    _HAS_ST = False

import config

# Rows per progress update when encoding a large batch. Chunking the call
# ourselves (rather than relying solely on sentence-transformers' internal
# tqdm bar) guarantees a visible, flushed print line no matter the
# terminal -- tqdm's \r-based bar can end up invisible or badly garbled in
# some Windows terminals/redirected output, which is why "no output" can
# still mean it's actively working.
_PROGRESS_CHUNK = 2000
_PROGRESS_MIN_ROWS = 500  # below this, just encode in one shot silently


class Embedder:
    _instance = None

    def __init__(self):
        if _HAS_ST:
            self.model = SentenceTransformer(config.EMBEDDING_MODEL_NAME)
        else:
            # Fallback so the API still boots in environments where the
            # heavy model hasn't been downloaded yet (e.g. CI, first run).
            self.model = None

    @classmethod
    def instance(cls) -> "Embedder":
        if cls._instance is None:
            cls._instance = Embedder()
        return cls._instance

    def encode(self, texts, show_progress=None):
        single = isinstance(texts, str)
        if single:
            texts = [texts]

        if self.model is not None:
            if show_progress is None:
                show_progress = len(texts) >= _PROGRESS_MIN_ROWS

            if not show_progress:
                vectors = self.model.encode(
                    texts, normalize_embeddings=True, show_progress_bar=False
                )
            else:
                vectors = self._encode_with_progress(texts)
        else:
            # Deterministic hash-based fallback embedding (dev-mode only,
            # NOT for production use) so the pipeline remains runnable
            # without network access to download SBERT weights.
            vectors = np.array([_hash_embedding(t) for t in texts])

        return vectors[0] if single else vectors

    def _encode_with_progress(self, texts):
        """Encodes in chunks, printing a plain (non-\\r, always-flushed)
        progress line after each chunk. This is deliberately not a
        tqdm-style in-place bar -- those can render as nothing at all (or
        as garbage) in some Windows consoles / redirected output, which
        looks identical to "hung"."""
        n = len(texts)
        chunks = []
        t0 = time.time()
        done = 0
        print(f"    encoding {n} rows in chunks of {_PROGRESS_CHUNK}...", flush=True)
        for start in range(0, n, _PROGRESS_CHUNK):
            chunk = texts[start:start + _PROGRESS_CHUNK]
            vecs = self.model.encode(chunk, normalize_embeddings=True, show_progress_bar=False)
            chunks.append(vecs)
            done += len(chunk)
            elapsed = time.time() - t0
            rate = done / elapsed if elapsed > 0 else 0.0
            eta_s = (n - done) / rate if rate > 0 else 0.0
            print(
                f"    encoded {done}/{n} ({100 * done / n:.0f}%) "
                f"| {rate:.0f} rows/s | elapsed {elapsed:.0f}s | eta {eta_s:.0f}s",
                flush=True,
            )
        return np.vstack(chunks)


def _hash_embedding(text: str, dim: int = config.EMBEDDING_DIM) -> np.ndarray:
    rng = np.random.default_rng(abs(hash(text)) % (2**32))
    vec = rng.normal(size=dim)
    return vec / np.linalg.norm(vec)


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    denom = (np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0:
        return 0.0
    return float(np.dot(a, b) / denom)