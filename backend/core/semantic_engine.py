"""
Layer B — Embedding similarity + dual-corpus context anchoring (Layer E half).

Embeds the incoming prompt and compares it against:
  1. the attack corpus (HackAPrompt/JailbreakBench-style examples)
  2. the benign-with-trigger-words corpus (over-defense calibration set)

If the prompt sits closer to the benign cluster than the attack cluster,
that pulls the effective attack-similarity score down even if a rule
matched — this is what prevents "ignore the typo" from being blocked
just because it contains the word "ignore".
"""
import os
import time
from dataclasses import dataclass
from typing import List, Optional

import numpy as np
import pandas as pd

try:
    import faiss
    _HAS_FAISS = True
except ImportError:
    _HAS_FAISS = False

import config
from models.embedding import Embedder, cosine_similarity


def _stage(msg):
    """Lightweight progress banner -- building the production singleton
    embeds the full attack corpus (hundreds of thousands of rows) and can
    silently sit there for minutes on CPU with zero output otherwise."""
    print(f"[SemanticEngine] {msg}", flush=True)


@dataclass
class SemanticResult:
    attack_similarity: float
    nearest_attack: Optional[str]
    nearest_attack_cluster: Optional[str]
    benign_similarity: float
    context_anchored_score: float  # attack_similarity, pulled down toward benign


class SemanticEngine:
    _instance = None

    def __init__(self, attack_texts=None, attack_clusters=None, benign_texts=None,
                 max_attack_rows=None, max_benign_rows=None):
        # Default (no args): load and index the FULL corpora from disk.
        # Correct for the runtime singleton, since production should index
        # every known attack example.
        #
        # attack_texts / attack_clusters / benign_texts let a caller
        # (models/train.py) supply a restricted subset instead, so a
        # standalone engine can be indexed on the TRAIN split only. Without
        # this, training-time feature extraction queries an index that
        # already contains the row being featurized -- data leakage that
        # inflates reported accuracy.
        #
        # max_attack_rows / max_benign_rows let a caller (e.g.
        # scripts/benchmark_latency.py --fast) cap how many rows of the
        # FULL corpora get loaded/embedded when building the singleton --
        # only used when attack_texts/benign_texts aren't already given.
        self.embedder = Embedder.instance()

        if attack_texts is None:
            self.attack_texts, self.attack_clusters, self.attack_vectors = self._load_corpus(
                config.ATTACK_CORPUS_PATH, text_col="text", cluster_col="cluster_name",
                max_rows=max_attack_rows, label="attack corpus",
            )
        else:
            self.attack_texts = list(attack_texts)
            self.attack_clusters = list(attack_clusters) if attack_clusters is not None else [None] * len(self.attack_texts)
            _stage(f"embedding {len(self.attack_texts)} supplied attack rows...")
            self.attack_vectors = (
                self.embedder.encode(self.attack_texts).astype("float32")
                if self.attack_texts else np.zeros((0, config.EMBEDDING_DIM), dtype="float32")
            )

        if benign_texts is None:
            self.benign_texts, _, self.benign_vectors = self._load_corpus(
                config.TRIGGER_BENIGN_CORPUS_PATH, text_col="text", cluster_col=None,
                max_rows=max_benign_rows, label="benign-trigger corpus",
            )
        else:
            self.benign_texts = list(benign_texts)
            _stage(f"embedding {len(self.benign_texts)} supplied benign rows...")
            self.benign_vectors = (
                self.embedder.encode(self.benign_texts).astype("float32")
                if self.benign_texts else np.zeros((0, config.EMBEDDING_DIM), dtype="float32")
            )

        _stage("building FAISS index...")
        t0 = time.time()
        self._attack_index = self._build_index(self.attack_vectors)
        self._benign_index = self._build_index(self.benign_vectors)
        _stage(f"index ready in {time.time() - t0:.1f}s "
               f"({len(self.attack_texts)} attack vectors, {len(self.benign_texts)} benign vectors)")

    @classmethod
    def instance(cls, max_attack_rows=None, max_benign_rows=None) -> "SemanticEngine":
        if cls._instance is None:
            if max_attack_rows or max_benign_rows:
                _stage(f"first call -- building singleton capped at "
                       f"max_attack_rows={max_attack_rows}, max_benign_rows={max_benign_rows}")
            cls._instance = SemanticEngine(max_attack_rows=max_attack_rows, max_benign_rows=max_benign_rows)
        elif max_attack_rows or max_benign_rows:
            _stage("instance() called with a row cap but the singleton already exists -- "
                   "cap ignored, reusing the existing index. Call SemanticEngine.reset() first if you "
                   "need to rebuild it with different limits.")
        return cls._instance

    @classmethod
    def reset(cls):
        """Drops the cached singleton so the next instance() call rebuilds
        it from scratch (e.g. with a different max_attack_rows cap)."""
        cls._instance = None

    @classmethod
    def for_training(cls, attack_texts, attack_clusters, benign_texts) -> "SemanticEngine":
        # Standalone (non-singleton) engine indexed ONLY on the given texts.
        # models/train.py calls this with the TRAIN split so the index
        # behind feature extraction never contains the row currently being
        # featurized -- the fix for the ~100%-accuracy leakage bug.
        return cls(attack_texts=attack_texts, attack_clusters=attack_clusters, benign_texts=benign_texts)

    def _load_corpus(self, path: str, text_col: str, cluster_col: Optional[str],
                      max_rows=None, label=""):
        if not os.path.exists(path):
            return [], [], np.zeros((0, config.EMBEDDING_DIM), dtype="float32")

        _stage(f"reading {label or path}...")
        t_read = time.time()
        df = pd.read_csv(path, low_memory=False)
        _stage(f"  {len(df)} rows loaded in {time.time() - t_read:.1f}s")

        if max_rows and len(df) > max_rows:
            df = df.sample(n=max_rows, random_state=42).reset_index(drop=True)
            _stage(f"  downsampled to {len(df)} rows (--fast/max_rows cap; "
                   f"latency numbers from a capped index are NOT representative of the full "
                   f"production corpus, use for a quick smoke test only)")

        texts = df[text_col].astype(str).tolist()
        clusters = df[cluster_col].astype(str).tolist() if cluster_col and cluster_col in df else [None] * len(texts)

        _stage(f"  SBERT-encoding {len(texts)} rows from {label or path} "
               f"(progress bar below if this is a big batch)...")
        t_enc = time.time()
        vectors = self.embedder.encode(texts).astype("float32") if texts else np.zeros((0, config.EMBEDDING_DIM), dtype="float32")
        _stage(f"  encoding done in {time.time() - t_enc:.1f}s")
        return texts, clusters, vectors

    def _build_index(self, vectors: np.ndarray):
        if not _HAS_FAISS or vectors.shape[0] == 0:
            return None
        index = faiss.IndexFlatIP(vectors.shape[1])  # cosine sim via normalized inner product
        index.add(vectors)
        return index

    def _search(self, index, vectors, query_vec, texts, clusters=None, k=1):
        if index is not None:
            scores, idxs = index.search(query_vec.reshape(1, -1).astype("float32"), k)
            best_idx = int(idxs[0][0]) if idxs.shape[1] > 0 and idxs[0][0] != -1 else None
            best_score = float(scores[0][0]) if best_idx is not None else 0.0
        elif len(texts) > 0:
            sims = [cosine_similarity(query_vec, v) for v in vectors]
            best_idx = int(np.argmax(sims))
            best_score = float(sims[best_idx])
        else:
            return None, 0.0, None

        nearest_text = texts[best_idx] if best_idx is not None else None
        nearest_cluster = clusters[best_idx] if clusters and best_idx is not None else None
        return nearest_text, best_score, nearest_cluster

    def _search_batch(self, index, vectors, query_vecs, texts, clusters=None, k=1):
        """Batched version of _search: one FAISS call for ALL query
        vectors instead of one call per row. With a large index (e.g.
        300K+ attack vectors after merging the full HackAPrompt dataset),
        calling index.search() once per row -- even though each
        individual search is fast -- adds up to a huge amount of time
        across hundreds of thousands of rows. FAISS is built to search
        many queries against an index in a single matrix operation, which
        is what this uses.

        Returns a list of (nearest_text, best_score, nearest_cluster)
        tuples, one per row in query_vecs, in the same order.
        """
        n = query_vecs.shape[0]
        if index is not None:
            scores, idxs = index.search(query_vecs.astype("float32"), k)
            results = []
            for i in range(n):
                best_idx = int(idxs[i][0]) if idxs.shape[1] > 0 and idxs[i][0] != -1 else None
                best_score = float(scores[i][0]) if best_idx is not None else 0.0
                nearest_text = texts[best_idx] if best_idx is not None else None
                nearest_cluster = clusters[best_idx] if clusters and best_idx is not None else None
                results.append((nearest_text, best_score, nearest_cluster))
            return results
        elif len(texts) > 0:
            # No-FAISS fallback: still one matrix multiply for everything,
            # not a per-row Python loop over cosine_similarity.
            vecs = np.asarray(vectors)
            sims = query_vecs @ vecs.T  # (n_queries, n_corpus) -- vectors are already normalized
            best_idxs = np.argmax(sims, axis=1)
            results = []
            for i in range(n):
                best_idx = int(best_idxs[i])
                best_score = float(sims[i, best_idx])
                nearest_text = texts[best_idx]
                nearest_cluster = clusters[best_idx] if clusters else None
                results.append((nearest_text, best_score, nearest_cluster))
            return results
        else:
            return [(None, 0.0, None)] * n

    def analyze(self, text: str) -> SemanticResult:
        query_vec = self.embedder.encode(text)
        return self._analyze_vec(query_vec)

    def analyze_batch(self, texts: List[str]) -> List[SemanticResult]:
        """Same as calling analyze() per text, but batches BOTH the SBERT
        encoding and the FAISS similarity search across all texts at
        once, instead of doing either one row at a time. With a large
        corpus (e.g. the full HackAPrompt dataset merged into
        attacks.csv), one-at-a-time encoding or one-at-a-time search can
        each independently turn a few-minute run into a multi-hour one --
        this avoids both.

        Use this instead of a loop over analyze() whenever you already
        have the full list of texts up front (e.g. training/evaluation),
        not just at live-request time where only one text is available.
        """
        if not texts:
            return []
        query_vecs = self.embedder.encode(list(texts)).astype("float32")
        if query_vecs.ndim == 1:
            query_vecs = query_vecs.reshape(1, -1)

        attack_hits = self._search_batch(
            self._attack_index, self.attack_vectors, query_vecs, self.attack_texts, self.attack_clusters
        )
        benign_hits = self._search_batch(
            self._benign_index, self.benign_vectors, query_vecs, self.benign_texts
        )

        results = []
        for (nearest_attack, attack_sim, cluster), (_, benign_sim, _) in zip(attack_hits, benign_hits):
            if benign_sim > attack_sim:
                anchored = max(0.0, attack_sim - (benign_sim - attack_sim))
            else:
                anchored = attack_sim
            results.append(SemanticResult(
                attack_similarity=round(attack_sim, 4),
                nearest_attack=nearest_attack,
                nearest_attack_cluster=cluster,
                benign_similarity=round(benign_sim, 4),
                context_anchored_score=round(anchored, 4),
            ))
        return results

    def _analyze_vec(self, query_vec: np.ndarray) -> SemanticResult:

        nearest_attack, attack_sim, cluster = self._search(
            self._attack_index, self.attack_vectors, query_vec, self.attack_texts, self.attack_clusters
        )
        _, benign_sim, _ = self._search(
            self._benign_index, self.benign_vectors, query_vec, self.benign_texts
        )

        # Context anchoring: if closer to benign cluster, discount attack similarity.
        if benign_sim > attack_sim:
            anchored = max(0.0, attack_sim - (benign_sim - attack_sim))
        else:
            anchored = attack_sim

        return SemanticResult(
            attack_similarity=round(attack_sim, 4),
            nearest_attack=nearest_attack,
            nearest_attack_cluster=cluster,
            benign_similarity=round(benign_sim, 4),
            context_anchored_score=round(anchored, 4),
        )