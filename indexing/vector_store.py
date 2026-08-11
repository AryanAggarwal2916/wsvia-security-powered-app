"""
ChromaDB persistent vector store wrapper.

Collection metadata schema (per chunk):
    - source_path: str
    - source_type: str
    - severity: str
    - chunk_id: str
    - document_name: str
    - heading: str
    - owasp_id: str
    - wstg_id: str
"""

import logging
from typing import Any, Sequence

from config import CHROMA_COLLECTION_NAME, CHROMA_PERSIST_DIR

logger = logging.getLogger(__name__)

_client = None
_collection = None


def get_collection():
    """Get or create the persistent Chroma collection."""
    global _client, _collection
    if _collection is None:
        import chromadb

        CHROMA_PERSIST_DIR.mkdir(parents=True, exist_ok=True)
        _client = chromadb.PersistentClient(path=str(CHROMA_PERSIST_DIR))
        _collection = _client.get_or_create_collection(CHROMA_COLLECTION_NAME)
    return _collection


def reset_collection():
    """Delete and recreate the Chroma collection for clean re-indexing."""
    global _client, _collection
    import chromadb

    CHROMA_PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    if _client is None:
        _client = chromadb.PersistentClient(path=str(CHROMA_PERSIST_DIR))

    try:
        _client.delete_collection(CHROMA_COLLECTION_NAME)
    except Exception as e:
        logger.debug(f"Collection delete skipped: {e}")

    _collection = _client.get_or_create_collection(CHROMA_COLLECTION_NAME)
    return _collection


def add_chunks(chunks: list[dict[str, Any]], embeddings: list[list[float]], batch_size: int = 100) -> None:
    """Add embedded chunks + metadata to the collection in batches of 100."""
    if not chunks:
        return

    collection = get_collection()

    total = len(chunks)
    for i in range(0, total, batch_size):
        batch_chunks = chunks[i : i + batch_size]
        batch_embeddings = embeddings[i : i + batch_size]

        ids = [c["chunk_id"] for c in batch_chunks]
        documents = [c["text"] for c in batch_chunks]

        metadatas = []
        for c in batch_chunks:
            meta = {
                "source_path": str(c.get("source_path", "")),
                "source_type": str(c.get("source_type", "")),
                "severity": str(c.get("severity", "")),
                "chunk_id": str(c.get("chunk_id", "")),
                "document_name": str(c.get("document_name", "")),
                "heading": str(c.get("heading", "")),
                "owasp_id": str(c.get("owasp_id") or ""),
                "wstg_id": str(c.get("wstg_id") or ""),
            }
            metadatas.append(meta)

        collection.add(ids=ids, embeddings=batch_embeddings, documents=documents, metadatas=metadatas)


def query(
    query_embedding: list[float],
    top_k: int = 5,
    source_type_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Query the collection for nearest chunks, optionally filtered by source_type."""
    collection = get_collection()

    where = None
    if source_type_filter and source_type_filter != "All":
        where = {"source_type": source_type_filter}

    raw_results = collection.query(
        query_embeddings=[query_embedding],
        n_results=top_k,
        where=where,
    )

    reshaped: list[dict[str, Any]] = []

    if raw_results and raw_results.get("documents"):
        docs = raw_results["documents"][0]
        metas = raw_results["metadatas"][0] if raw_results.get("metadatas") else [{}] * len(docs)
        dists = raw_results["distances"][0] if raw_results.get("distances") else [0.0] * len(docs)
        ids = raw_results["ids"][0] if raw_results.get("ids") else [""] * len(docs)

        for doc_text, meta, dist, chunk_id in zip(docs, metas, dists, ids):
            reshaped.append({
                "text": doc_text,
                "metadata": meta,
                "distance": dist,
                "chunk_id": chunk_id,
            })

    return reshaped

def get_by_document_name(document_name: str) -> list[dict[str, Any]]:
    """Exact metadata lookup — bypasses similarity search entirely."""
    collection = get_collection()
    raw = collection.get(
        where={"document_name": document_name},
        include=["documents", "metadatas"],
    )

    reshaped: list[dict[str, Any]] = []
    if raw and raw.get("documents"):
        docs = raw["documents"]
        metas = raw["metadatas"] if raw.get("metadatas") else [{}] * len(docs)
        ids = raw["ids"] if raw.get("ids") else [""] * len(docs)

        for doc_text, meta, chunk_id in zip(docs, metas, ids):
            reshaped.append({
                "text": doc_text,
                "metadata": meta,
                "distance": 0.0,  # exact match, treat as perfectly relevant
                "chunk_id": chunk_id,
            })

    return reshaped


def delete_by_document_name(document_name: str) -> int:
    """Delete all chunks matching document_name from Chroma collection.

    Returns the number of deleted chunks.
    """
    collection = get_collection()
    matching = collection.get(
        where={"document_name": document_name},
        include=[],
    )
    matching_ids = matching.get("ids", []) if matching else []
    if matching_ids:
        collection.delete(ids=matching_ids)
    return len(matching_ids)


def get_all_documents_metadata() -> list[dict[str, Any]]:
    """Retrieve unique document metadata records currently stored in ChromaDB."""
    collection = get_collection()
    raw = collection.get(include=["metadatas"])
    metas = raw.get("metadatas", []) if raw else []

    docs_map: dict[str, dict[str, Any]] = {}
    for meta in metas:
        if not meta:
            continue
        doc_name = meta.get("document_name", "unknown")
        if doc_name not in docs_map:
            docs_map[doc_name] = {
                "document_name": doc_name,
                "source_type": meta.get("source_type", "unknown"),
                "source_path": meta.get("source_path", ""),
                "owasp_id": meta.get("owasp_id") or "",
                "wstg_id": meta.get("wstg_id") or "",
                "severity": meta.get("severity", "n/a"),
                "chunk_count": 1,
            }
        else:
            docs_map[doc_name]["chunk_count"] += 1

    return list(docs_map.values())

