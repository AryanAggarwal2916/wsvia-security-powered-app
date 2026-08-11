"""
Document loaders for the Ingestion layer.

Each loader takes a file path and returns a list of raw "documents":
    {
        "text": str,
        "source_path": str,
        "source_type": str,   # "owasp_top10" | "cheat_sheet" | "testing_guide"
                              # | "internal_audit" | "secure_coding_guide"
                              # | "cve_summary" | "git_history"
    }

Chunking (splitting these into smaller pieces + attaching metadata) happens
in chunking.py, not here. Keep these loaders "dumb": read + minimally clean.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def load_markdown(path: str | Path, source_type: str) -> dict[str, Any]:
    """Read a Markdown file into a raw document dict.

    - Reads UTF-8 text.
    - Strips front-matter (--- blocks) if present.
    - Strips MkDocs image attributes and HTML tags while preserving table cell text.
    - Returns {"text": ..., "source_path": str(path), "source_type": source_type, "document_name": path.stem}
    """
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")

    # Strip YAML front-matter at start of document if present
    text = re.sub(r"^---\s*\n.*?\n---\s*\n?", "", text, flags=re.DOTALL)

    # Strip image directives completely (plain ![alt](url) and MkDocs ![alt](url){...})
    text = re.sub(r"!\[.*?\]\([^)]*\)(\{[\s\S]*?\})?", "", text)

    # Strip HTML tags but preserve inner text (e.g. <th>Cell</th> -> Cell)
    text = re.sub(r"<[^>]+>", " ", text)

    # Collapse multiple spaces on lines while preserving newlines
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines()]
    clean_text = "\n".join(lines).strip()

    return {
        "text": clean_text,
        "source_path": str(file_path),
        "source_type": source_type,
        "document_name": file_path.stem,
    }


def load_pdf(path: str | Path, source_type: str) -> dict[str, Any]:
    """Read a PDF file into a raw document dict using PyMuPDF (fitz).

    Working stub for PDF files.
    """
    file_path = Path(path)
    text = ""
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(file_path)
        pages_text = [page.get_text() for page in doc]
        text = "\n--- Page Break ---\n".join(pages_text)
    except Exception as e:
        logger.warning(f"Could not load PDF '{file_path}': {e}")

    return {
        "text": text,
        "source_path": str(file_path),
        "source_type": source_type,
        "document_name": file_path.stem,
    }


def load_json(path: str | Path, source_type: str) -> list[dict[str, Any]]:
    """Read a JSON file (e.g. NVD CVE corpus) into raw document dicts.

    Supports two JSON shapes:

    1. **WSVIA CVE corpus format** — a JSON array whose items contain at least
       the keys ``cve_id``, ``description``, and ``owasp_category``.  Each
       record is rendered as structured Markdown prose so that downstream
       chunking and retrieval work correctly:

       - ``document_name`` is set to the CVE ID (e.g. ``CVE-2021-44228``).
       - The OWASP category tag (e.g. ``A05_2025``) is embedded in the text so
         that ``extract_owasp_id()`` in chunking.py picks it up automatically.
       - The CVSS score is embedded as ``CVSS Score: X.X`` so that
         ``infer_severity()`` in chunking.py can override the default severity.
       - ``reference_urls`` from the NVD record are stored in the returned dict
         but are NOT included in the chunk text, preventing them from appearing
         as fabricated citations in generated answers.

    2. **Generic JSON** (any other dict or list shape) — falls back to
       ``str(item)`` stringification (preserves compatibility with any future
       JSON corpus files that do not follow the CVE schema).
    """
    file_path = Path(path)
    results: list[dict[str, Any]] = []

    try:
        content = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning(f"Could not load JSON '{file_path}': {e}")
        return results

    # ------------------------------------------------------------------
    # WSVIA CVE corpus: list of per-CVE dicts with expected keys
    # ------------------------------------------------------------------
    _CVE_REQUIRED_KEYS = {"cve_id", "description", "owasp_category"}
    if (
        isinstance(content, list)
        and content
        and _CVE_REQUIRED_KEYS.issubset(content[0].keys())
    ):
        for record in content:
            cve_id: str = record.get("cve_id", "UNKNOWN")
            description: str = record.get("description", "").strip()
            owasp_cat: str = record.get("owasp_category", "")   # e.g. "A05:2025"
            vuln_class: str = record.get("vulnerability_class", "")
            cvss_score = record.get("cvss_score")               # float | None
            severity: str = record.get("severity", "medium")
            cwe_ids: list = record.get("cwe_ids", [])
            published: str = record.get("published_date", "")
            # reference_urls stored as metadata only — not embedded in text
            reference_urls: list = record.get("reference_urls", [])

            # Embed OWASP tag as "A05_2025" (underscore) so extract_owasp_id()
            # regex r"(A\d{2})[_-](\d{4})" matches it from the text.
            owasp_tag = owasp_cat.replace(":", "_") if owasp_cat else ""

            lines = [
                f"# {cve_id} — {vuln_class}",
                "",
                f"**OWASP Category:** {owasp_cat} ({owasp_tag}) — {vuln_class}",
            ]
            if published:
                lines.append(f"**Published:** {published}")
            if cvss_score is not None:
                lines.append(f"**CVSS Score: {cvss_score:.1f}** | Severity: {severity}")
            if cwe_ids:
                lines.append(f"**CWE:** {', '.join(cwe_ids)}")
            lines += ["", description]

            text = "\n".join(lines).strip()

            results.append({
                "text": text,
                "source_path": str(file_path),
                "source_type": source_type,
                "document_name": cve_id,          # CVE ID as document name for citation whitelist
                # Extra metadata passed through (chunking.py ignores unknown keys)
                "cve_id": cve_id,
                "owasp_category": owasp_cat,
                "severity_override": severity,
                # reference_urls not in text; stored here for traceability only
                "reference_urls": reference_urls,
            })
        return results

    # ------------------------------------------------------------------
    # Fallback: generic JSON list or dict
    # ------------------------------------------------------------------
    if isinstance(content, list):
        for idx, item in enumerate(content):
            results.append({
                "text": str(item),
                "source_path": str(file_path),
                "source_type": source_type,
                "document_name": f"{file_path.stem}_{idx}",
            })
    elif isinstance(content, dict):
        results.append({
            "text": str(content),
            "source_path": str(file_path),
            "source_type": source_type,
            "document_name": file_path.stem,
        })

    return results


def load_source_directory(root: str | Path) -> list[dict[str, Any]]:
    """Walk data/corpus/<source_type>/ subfolders and dispatch to the right
    loader based on file extension + folder name.

    Skips non-existent subfolders with a logged warning.
    Uses rglob("*.md") per source folder to recursively find nested markdown files.
    """
    root_path = Path(root)
    documents: list[dict[str, Any]] = []

    try:
        from config import SOURCE_TYPES
        source_types = SOURCE_TYPES
    except ImportError:
        source_types = tuple(p.name for p in root_path.iterdir() if p.is_dir()) if root_path.exists() else ()

    for source_type in source_types:
        folder_path = root_path / source_type
        if not folder_path.exists():
            logger.warning(f"Corpus folder '{folder_path}' does not exist on disk. Skipping.")
            continue

        # Load Markdown files recursively
        for md_file in sorted(folder_path.rglob("*.md")):
            try:
                doc = load_markdown(md_file, source_type)
                documents.append(doc)
            except Exception as e:
                logger.error(f"Error loading Markdown file '{md_file}': {e}")

        # Load PDF files recursively
        for pdf_file in sorted(folder_path.rglob("*.pdf")):
            try:
                doc = load_pdf(pdf_file, source_type)
                documents.append(doc)
            except Exception as e:
                logger.error(f"Error loading PDF file '{pdf_file}': {e}")

        # Load JSON files recursively
        for json_file in sorted(folder_path.rglob("*.json")):
            try:
                docs = load_json(json_file, source_type)
                documents.extend(docs)
            except Exception as e:
                logger.error(f"Error loading JSON file '{json_file}': {e}")

    return documents
