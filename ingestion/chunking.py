"""
Chunking strategy for the Ingestion layer.

Heading-aware chunking:
Splits raw documents on #/##/### headings, inheriting headings as chunk prefixes.
Sub-splits by paragraph with overlap if a section exceeds CHUNK_SIZE_TOKENS (256 tokens).
Attaches metadata: source_path, source_type, severity, chunk_id, document_name, owasp_id, wstg_id.
"""

import logging
import re
from typing import Any

from config import CHUNK_OVERLAP_TOKENS, CHUNK_SIZE_TOKENS, SOURCE_SEVERITY

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "informational")


def extract_owasp_id(doc: dict[str, Any]) -> str | None:
    """Extract OWASP Top 10 ID (e.g. A05:2025) from filename or text."""
    doc_name = doc.get("document_name", "")
    text = doc.get("text", "")

    # Match A01_2025 or A01-2025 in filename
    m = re.search(r"(A\d{2})[_-](\d{4})", doc_name, re.IGNORECASE)
    if m:
        return f"{m.group(1).upper()}:{m.group(2)}"

    # Match A01:2025 or A01_2025 in text
    m_text = re.search(r"(A\d{2})[:_-](\d{4})", text, re.IGNORECASE)
    if m_text:
        return f"{m_text.group(1).upper()}:{m_text.group(2)}"

    return None


def extract_wstg_id(doc: dict[str, Any]) -> str | None:
    """Extract WSTG ID (e.g. WSTG-INPV-01) from filename or text."""
    content = doc.get("document_name", "") + " " + doc.get("text", "")
    m = re.search(r"(WSTG-[A-Z0-9]+-\d{2})", content, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    return None


def infer_severity(doc: dict[str, Any], chunk_text: str) -> str:
    """Best-effort severity tag for a chunk.

    Defaults by source_type from config, overridden if CVSS score is present.
    """
    source_type = doc.get("source_type", "")
    default_sev = SOURCE_SEVERITY.get(source_type, "high")

    cvss_match = re.search(r"cvss\s*(?:score)?:?\s*(\d+(?:\.\d+)?)", chunk_text, re.IGNORECASE)
    if cvss_match:
        try:
            score = float(cvss_match.group(1))
            if score >= 9.0:
                return "critical"
            elif score >= 7.0:
                return "high"
            elif score >= 4.0:
                return "medium"
            elif score > 0.0:
                return "low"
        except ValueError:
            pass

    return default_sev


def split_text_by_paragraphs(text: str, max_words: int = 180, overlap_words: int = 25) -> list[str]:
    """Sub-split large section text by paragraphs with overlap."""
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    if not paragraphs:
        return [text]

    chunks: list[str] = []
    current_paras: list[str] = []
    current_word_count = 0

    for p in paragraphs:
        p_words = len(p.split())
        if current_word_count + p_words <= max_words:
            current_paras.append(p)
            current_word_count += p_words
        else:
            if current_paras:
                chunks.append("\n\n".join(current_paras))

            # Keep overlap paragraphs from tail of current_paras
            overlap_paras: list[str] = []
            overlap_count = 0
            for prev_p in reversed(current_paras):
                w_count = len(prev_p.split())
                if overlap_count + w_count <= overlap_words:
                    overlap_paras.insert(0, prev_p)
                    overlap_count += w_count
                else:
                    break
            current_paras = overlap_paras + [p]
            current_word_count = sum(len(x.split()) for x in current_paras)

    if current_paras:
        chunks.append("\n\n".join(current_paras))

    return chunks if chunks else [text]


def chunk_document(
    doc: dict[str, Any],
    chunk_size: int = CHUNK_SIZE_TOKENS,
    overlap: int = CHUNK_OVERLAP_TOKENS,
) -> list[dict[str, Any]]:
    """Heading-aware document chunking.

    Splits on headings (#, ##, ###) and sub-splits paragraphs if sections exceed chunk_size.
    """
    text = doc.get("text", "")
    source_path = doc.get("source_path", "")
    source_type = doc.get("source_type", "")
    doc_name = doc.get("document_name", "")

    owasp_id = extract_owasp_id(doc)
    wstg_id = extract_wstg_id(doc)

    if source_type == "owasp_top10" and owasp_id is None:
        logger.info(f"owasp_id is None for file: {doc_name}")
    if source_type == "testing_guide" and wstg_id is None:
        logger.info(f"wstg_id is None for file: {doc_name}")

    heading_pattern = r"(?m)^(#{1,3}\s+.*$)"
    sections = re.split(heading_pattern, text)

    raw_chunks: list[dict[str, str]] = []
    current_heading = doc_name

    idx = 0
    while idx < len(sections):
        part = sections[idx].strip()
        if not part:
            idx += 1
            continue

        if re.match(r"^#{1,3}\s+", part):
            current_heading = part.lstrip("#").strip()
            idx += 1
            if idx < len(sections):
                body = sections[idx].strip()
                idx += 1
            else:
                body = ""
        else:
            body = part
            idx += 1

        if body:
            heading_prefix = f"[{doc_name}] [{current_heading}]\n" if current_heading else f"[{doc_name}]\n"
            chunk_body = f"{heading_prefix}{body}"

            max_words = int(chunk_size * 0.7)
            overlap_words = int(overlap * 0.7)

            if len(chunk_body.split()) > max_words:
                sub_bodies = split_text_by_paragraphs(body, max_words=max_words, overlap_words=overlap_words)
                for sub in sub_bodies:
                    raw_chunks.append({"heading": current_heading, "text": f"{heading_prefix}{sub}"})
            else:
                raw_chunks.append({"heading": current_heading, "text": chunk_body})

    if not raw_chunks:
        raw_chunks.append({"heading": doc_name, "text": f"[{doc_name}]\n{text}"})

    final_chunks: list[dict[str, Any]] = []
    for chunk_idx, item in enumerate(raw_chunks):
        c_text = item["text"]
        sev = infer_severity(doc, c_text)
        # Include doc_name in the ID to ensure uniqueness when multiple docs
        # share the same source_path (e.g. 61 CVEs all from cve_corpus.json).
        chunk_id = f"{source_path}::{doc_name}::{chunk_idx}"

        final_chunks.append({
            "text": c_text,
            "source_path": source_path,
            "source_type": source_type,
            "severity": sev,
            "chunk_id": chunk_id,
            "document_name": doc_name,
            "heading": item["heading"],
            "owasp_id": owasp_id,
            "wstg_id": wstg_id,
        })

    return final_chunks


def chunk_all(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Chunk all raw documents and return a flattened list of chunks."""
    all_chunks: list[dict[str, Any]] = []
    for doc in documents:
        chunks = chunk_document(doc, chunk_size=CHUNK_SIZE_TOKENS, overlap=CHUNK_OVERLAP_TOKENS)
        all_chunks.extend(chunks)
    return all_chunks

