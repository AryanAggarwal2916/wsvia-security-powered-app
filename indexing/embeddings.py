"""
Embedding model wrapper (sentence-transformers, all-MiniLM-L6-v2).

Kept as a thin wrapper so the rest of the codebase never imports
sentence_transformers directly.
"""

from typing import Sequence
from config import EMBEDDING_MODEL_NAME

_model = None  # lazy-loaded singleton


def get_model():
    """Load (once) and return the sentence-transformers model."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(EMBEDDING_MODEL_NAME)
    return _model


def embed_texts(texts: Sequence[str]) -> list[list[float]]:
    """Embed a batch of chunk texts."""
    if not texts:
        return []
    model = get_model()
    embeddings = model.encode(list(texts), normalize_embeddings=True, show_progress_bar=False)
    return embeddings.tolist()

