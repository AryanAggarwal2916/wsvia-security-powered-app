"""
Central config. Import from here rather than hardcoding paths/model names
in individual modules, so Phase 2 tuning (chunk size, top_k, model swaps)
is a one-file change.
"""

from pathlib import Path

# --- Paths -------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent
CORPUS_DIR = PROJECT_ROOT / "data" / "corpus"
CHROMA_PERSIST_DIR = PROJECT_ROOT / "data" / "chroma_db"

# --- Ingestion -----------------------------------------------------------
CHUNK_SIZE_TOKENS = 256  # matches all-MiniLM-L6-v2's max sequence length
CHUNK_OVERLAP_TOKENS = 32

# --- Indexing ------------------------------------------------------------
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
CHROMA_COLLECTION_NAME = "wsvia_corpus"

# --- Retrieval -----------------------------------------------------------
DEFAULT_TOP_K = 5

# --- Generation ------------------------------------------------------------
GROQ_MODEL = "llama-3.1-8b-instant"
GROQ_API_KEY_ENV_VAR = "GROQ_API_KEY"
MAX_CHAT_HISTORY_TURNS = 3

# --- Corpus source types (must match folder names under data/corpus/) ----
SOURCE_TYPES = (
    "owasp_top10",
    "cheat_sheets",
    "testing_guide",
    "internal_audit",
    "secure_coding_guide",
    "cve_summaries",
    "git_history",
)

# --- Severity ---------------------------------------------------------------
SEVERITY_LEVELS = ("critical", "high", "medium", "low", "informational")

# Default severity by source type (corpus priority table)
SOURCE_SEVERITY = {
    "owasp_top10": "critical",
    "cheat_sheets": "high",
    "testing_guide": "high",
    "internal_audit": "high",
    "secure_coding_guide": "high",
    "cve_summaries": "medium",
    "git_history": "medium",
}
