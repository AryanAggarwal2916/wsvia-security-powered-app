"""
Stage 7 — per-config worker (called as a subprocess by retrieval_tuning.py).

Usage (internal only, do not call directly):
  python scripts/_tuning_worker.py <chunk_size> <top_k> <config_label>

Prints one JSON line per query to stdout, then exits.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

chunk_size = int(sys.argv[1])
top_k = int(sys.argv[2])
config_label = sys.argv[3]

# Override CHUNK_SIZE_TOKENS before any project import reads it
import config as cfg
cfg.CHUNK_SIZE_TOKENS = chunk_size

from ingestion.loaders import load_source_directory
from ingestion.chunking import chunk_all
from indexing.embeddings import embed_texts
from indexing.vector_store import add_chunks, reset_collection, get_collection
from retrieval.retriever import retrieve

QUERIES: list[tuple[str, list[str]]] = [
    (
        "How do I prevent SQL injection?",
        ["SQL_Injection_Prevention_Cheat_Sheet", "A05_2025-Injection", "Injection"],
    ),
    (
        "What is broken access control?",
        ["A01_2025-Broken_Access_Control", "Broken_Access"],
    ),
    (
        "How to test for reflected XSS?",
        ["Reflected_Cross_Site_Scripting", "Cross_Site_Scripting", "XSS"],
    ),
    (
        "CSRF prevention best practices",
        ["Cross-Site_Request_Forgery_Prevention", "CSRF"],
    ),
    (
        "Session management security",
        ["Session_Management", "Session_Fixation", "session"],
    ),
]


def _hit(results: list[dict], expected_keywords: list[str]) -> bool:
    for r in results:
        doc = r.get("metadata", {}).get("document_name", "").lower()
        path = r.get("metadata", {}).get("source_path", "").lower()
        for kw in expected_keywords:
            if kw.lower() in doc or kw.lower() in path:
                return True
    return False


def rebuild():
    print(f"[worker] Rebuilding index (chunk_size={chunk_size})...", file=sys.stderr, flush=True)
    collection = reset_collection()
    docs = load_source_directory("data/corpus")
    chunks = chunk_all(docs)
    texts = [c["text"] for c in chunks]
    embeddings = embed_texts(texts)
    add_chunks(chunks, embeddings, batch_size=100)
    count = collection.count()
    print(f"[worker] Indexed {count} chunks.", file=sys.stderr, flush=True)
    return count


needs_rebuild = "--rebuild" in sys.argv

if needs_rebuild:
    chunk_count = rebuild()
else:
    chunk_count = get_collection().count()
    print(f"[worker] Using existing index: {chunk_count} chunks.", file=sys.stderr, flush=True)

rows = []
for query_text, expected in QUERIES:
    results = retrieve(query_text, top_k=top_k)
    top1_meta = results[0].get("metadata", {}) if results else {}
    top1_doc = top1_meta.get("document_name", "—")
    top1_dist = results[0].get("distance", -1.0) if results else -1.0
    hit = _hit(results, expected)
    rows.append({
        "query": query_text,
        "top1_doc": top1_doc,
        "top1_dist": top1_dist,
        "hit": hit,
        "config": config_label,
    })
    print(f"[worker]   {query_text[:38]:<40} -> {top1_doc[:43]:<45} {'HIT' if hit else 'MISS'}", file=sys.stderr, flush=True)

# Emit result as one JSON line to stdout
print(json.dumps({"chunk_count": chunk_count, "rows": rows}))
