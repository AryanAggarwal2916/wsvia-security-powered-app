"""
Retrieval layer: query -> top-k relevant chunks.
"""

from typing import Any
from indexing.embeddings import embed_texts
from indexing.vector_store import query as vector_query


import re

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CVE_ALIASES = {
    "log4shell": "CVE-2021-44228",
    "log4j": "CVE-2021-44228",
    "zerologon": "CVE-2020-1472",
    "proxylogon": "CVE-2021-27065",
    "spring4shell": "CVE-2022-22965",
    "curveball": "CVE-2020-0601",
    "heartbleed": "CVE-2014-0160",
    "pwnkit": "CVE-2021-4034",
    "dirty pipe": "CVE-2022-0847",
}


def retrieve(
    query_text: str,
    top_k: int = 5,
    source_type_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Embed the query and fetch top-k matching chunks."""
    if not query_text or not query_text.strip():
        return []

    cve_id = None
    cve_match = CVE_PATTERN.search(query_text)
    if cve_match:
        cve_id = cve_match.group(0).upper()
    else:
        query_lower = query_text.lower()
        for alias, mapped_id in CVE_ALIASES.items():
            if alias in query_lower:
                cve_id = mapped_id
                break

    if cve_id:
        from indexing.vector_store import get_by_document_name
        exact_hits = get_by_document_name(cve_id)
        if exact_hits:
            return exact_hits[:top_k]

    from retrieval.structured_query import structured_cve_query
    structured_hits = structured_cve_query(query_text, top_k=top_k)
    if structured_hits is not None:
        return structured_hits

    embeddings = embed_texts([query_text])
    ...

    embeddings = embed_texts([query_text])
    if not embeddings:
        return []

    query_embedding = embeddings[0]
    results = vector_query(
        query_embedding,
        top_k=top_k,
        source_type_filter=source_type_filter,
    )
    return results

def get_related_vulnerabilities(source_chunk_metadata: dict[str, Any], top_k: int = 3) -> list[dict[str, Any]]:
    """Suggest related vulnerabilities given a chunk metadata."""
    if not source_chunk_metadata:
        return []

    owasp_id = source_chunk_metadata.get("owasp_id")
    heading = source_chunk_metadata.get("heading")
    doc_name = source_chunk_metadata.get("document_name")
    source_path = source_chunk_metadata.get("source_path")

    search_query = f"{owasp_id or ''} {heading or ''} {doc_name or ''} vulnerability prevention remediation".strip()
    if not search_query:
        return []

    candidates = retrieve(search_query, top_k=top_k + 5)

    related = []
    for item in candidates:
        if item.get("metadata", {}).get("source_path") != source_path:
            related.append(item)
        if len(related) >= top_k:
            break

    return related if related else candidates[:top_k]

