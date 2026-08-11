"""
Structured query layer: handles aggregation/list-style CVE questions
that vector similarity search can't answer (filtering, sorting, "most X").
Returns None if the query doesn't match a structured intent, so callers
can fall through to normal retrieval.
"""

import json
import re
from pathlib import Path
from typing import Any

CVE_CORPUS_PATH = Path("data/corpus/cve_summaries/cve_corpus.json")

_cve_data_cache: list[dict] | None = None


def _load_cve_data() -> list[dict]:
    global _cve_data_cache
    if _cve_data_cache is None:
        with open(CVE_CORPUS_PATH, encoding="utf-8") as f:
            _cve_data_cache = json.load(f)
    return _cve_data_cache


MOST_SEVERE_PATTERN = re.compile(
    r"most severe|highest severity|highest cvss|worst vulnerability", re.IGNORECASE
)
OWASP_CAT_PATTERN = re.compile(r"A0[1-9]:2025", re.IGNORECASE)
CVSS_THRESHOLD_PATTERN = re.compile(
    r"cvss\D{0,20}?(\d+(?:\.\d+)?)\D{0,15}?(?:or higher|or above|or more|\+)"
    r"|(?:above|over|higher than|at least|greater than)\D{0,10}?(\d+(?:\.\d+)?)\D{0,10}?cvss",
    re.IGNORECASE,
)


def structured_cve_query(query_text: str, top_k: int = 10) -> list[dict[str, Any]] | None:
    """Return synthetic chunks for aggregation-style queries, or None if not applicable."""
    data = _load_cve_data()

    if MOST_SEVERE_PATTERN.search(query_text):
        matches = sorted(data, key=lambda e: e.get("cvss_score", 0) or 0, reverse=True)
        return _to_chunks(matches[:top_k])

    cat_match = OWASP_CAT_PATTERN.search(query_text)
    cvss_match = CVSS_THRESHOLD_PATTERN.search(query_text)

    if cat_match and cvss_match:
        threshold = float(cvss_match.group(1) or cvss_match.group(2))
        cat = cat_match.group(0).upper()
        matches = [
            e for e in data
            if e.get("owasp_category", "").upper() == cat
            and (e.get("cvss_score") or 0) >= threshold
        ]
        matches = sorted(matches, key=lambda e: e.get("cvss_score", 0) or 0, reverse=True)
        if matches:
            return _to_chunks(matches[:top_k])
        return []  # legit "zero results" — different from "no structured intent detected"

    return None


def _to_chunks(entries: list[dict]) -> list[dict[str, Any]]:
    chunks = []
    for e in entries:
        text = (
            f"[{e['cve_id']}] {e.get('vulnerability_class', '')}\n"
            f"OWASP Category: {e.get('owasp_category', '')}\n"
            f"CVSS Score: {e.get('cvss_score')} | Severity: {e.get('severity')}\n"
            f"CWE: {', '.join(e.get('cwe_ids', []))}\n"
            f"Published: {e.get('published_date', '')}\n\n"
            f"{e.get('description', '')}"
        )
        meta = {
            "document_name": e.get("cve_id"),
            "source_type": "cve_summaries",
            "severity": e.get("severity", ""),
            "owasp_id": e.get("owasp_category", ""),
            "heading": f"{e.get('cve_id')} — {e.get('vulnerability_class', '')}",
            "source_path": "data/corpus/cve_summaries/cve_corpus.json",
        }
        chunks.append({
            "text": text,
            "metadata": meta,
            "distance": 0.0,
            "chunk_id": f"structured::{e.get('cve_id')}",
        })
    return chunks