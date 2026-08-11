"""
Document Library tab for WSVIA Streamlit UI.

Provides two sections on one page:
A) Browse view (read-only): list all indexed source documents, grouped by category/source_type.
B) Manage view (gated): passcode-protected management interface for uploading new documents
   (with duplicate prompt, spinner, and ingestion/embedding) and deleting documents from
   ChromaDB + disk.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import streamlit as st
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")
load_dotenv()

from config import CORPUS_DIR, SOURCE_TYPES
from indexing.embeddings import embed_texts
from indexing.vector_store import (
    add_chunks,
    delete_by_document_name,
    get_all_documents_metadata,
    get_by_document_name,
)
from ingestion.chunking import chunk_all
from ingestion.loaders import load_json, load_markdown, load_pdf

logger = logging.getLogger(__name__)

CATEGORY_LABELS: dict[str, str] = {
    "owasp_top10": "OWASP Top 10",
    "cheat_sheets": "OWASP Cheat Sheets",
    "testing_guide": "OWASP Testing Guide (WSTG)",
    "internal_audit": "Internal Security Audits",
    "secure_coding_guide": "Secure Coding Guidelines",
    "cve_summaries": "CVE & Vulnerability Database",
    "git_history": "Git History & Commit Logs",
}


def _delete_source_file_from_disk(doc_name: str, source_path_str: str) -> None:
    """Delete or update underlying source file on disk."""
    if not source_path_str:
        return
    path = Path(source_path_str)
    if not path.exists():
        return

    # Handle composite JSON files (e.g. cve_corpus.json containing multiple CVEs)
    if path.suffix.lower() == ".json":
        try:
            content = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(content, list) and content and isinstance(content[0], dict):
                filtered = [
                    rec
                    for rec in content
                    if rec.get("cve_id") != doc_name and rec.get("document_name") != doc_name
                ]
                if len(filtered) < len(content):
                    if filtered:
                        path.write_text(json.dumps(filtered, indent=2), encoding="utf-8")
                    else:
                        path.unlink(missing_ok=True)
                    return
        except Exception as e:
            logger.warning(f"Error updating JSON file '{path}': {e}")

    # Handle single file (markdown, pdf, standalone json)
    try:
        path.unlink(missing_ok=True)
    except Exception as e:
        logger.warning(f"Could not remove file '{path}': {e}")


def render_browse_view(docs_metadata: list[dict]) -> None:
    """Section A: Read-only Browse view grouped by category."""
    st.markdown("### 📚 Browse Indexed Documents")
    st.caption("Read-only list of all currently indexed security documentation in ChromaDB.")

    if not docs_metadata:
        st.info("No documents are currently indexed in ChromaDB.")
        return

    # Group documents by source_type
    grouped: dict[str, list[dict]] = {}
    for doc in docs_metadata:
        stype = doc.get("source_type", "other")
        grouped.setdefault(stype, []).append(doc)

    # Summary metrics
    total_docs = len(docs_metadata)
    total_chunks = sum(d.get("chunk_count", 0) for d in docs_metadata)

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Indexed Documents", total_docs)
    with col2:
        st.metric("Total Vector Chunks", total_chunks)

    st.markdown("---")

    # Render groups
    for stype in SOURCE_TYPES:
        docs = grouped.get(stype, [])
        if not docs:
            continue

        label = CATEGORY_LABELS.get(stype, stype.replace("_", " ").title())
        with st.expander(f"📁 **{label}** ({len(docs)} documents)", expanded=True):
            for d in sorted(docs, key=lambda x: x["document_name"]):
                doc_name = d["document_name"]
                chunks_cnt = d["chunk_count"]
                sev = d.get("severity", "n/a").upper()
                owasp = d.get("owasp_id", "")
                wstg = d.get("wstg_id", "")

                meta_tags = [f"Chunks: `{chunks_cnt}`", f"Severity: `{sev}`"]
                if owasp:
                    meta_tags.append(f"OWASP: `{owasp}`")
                if wstg:
                    meta_tags.append(f"WSTG: `{wstg}`")

                tags_str = " · ".join(meta_tags)

                st.markdown(
                    f"""
                    <div style="padding: 8px 12px; border-left: 3px solid #39FF88; margin-bottom: 8px; background: rgba(57, 255, 136, 0.03);">
                        <strong style="color: #E8F5EA;">{doc_name}</strong><br/>
                        <span style="font-size: 0.78rem; color: #6B8F72;">{tags_str}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )


def render_manage_view(docs_metadata: list[dict]) -> None:
    """Section B: Gated Manage view (upload & delete documents)."""
    st.markdown("### ⚙️ Manage Document Library")
    st.caption("Passcode-protected control panel for ingesting new files and removing indexed documents.")

    expected_passcode = os.environ.get("ADMIN_PASSCODE")
    if not expected_passcode:
        st.warning(
            "🔒 **Management Features Disabled**: `ADMIN_PASSCODE` environment variable is not configured. "
            "To enable document upload and deletion, please set `ADMIN_PASSCODE` in your `.env` file."
        )
        return

    # Passcode gate
    if not st.session_state.get("admin_unlocked", False):
        st.info("Enter the admin passcode to unlock document management controls.")
        passcode_input = st.text_input("Admin Passcode", type="password", key="admin_passcode_input")
        if st.button("Unlock Controls", key="unlock_passcode_btn"):
            if passcode_input == expected_passcode:
                st.session_state["admin_unlocked"] = True
                st.success("Access granted!")
                st.rerun()
            else:
                st.error("Invalid passcode. Access denied.")
        return

    # Admin unlocked interface
    st.success("🔓 Admin Access Unlocked")

    # Upload section
    st.markdown("#### 📤 Upload & Ingest New Document")
    target_source_type = st.selectbox(
        "Select Target Corpus Category",
        options=SOURCE_TYPES,
        format_func=lambda s: CATEGORY_LABELS.get(s, s),
        key="upload_source_type_select",
    )

    uploaded_file = st.file_uploader(
        "Choose file to ingest (.md, .pdf, .json)",
        type=["md", "pdf", "json"],
        key="doc_file_uploader",
    )

    if uploaded_file is not None:
        file_stem = Path(uploaded_file.name).stem
        existing_hits = get_by_document_name(file_stem)

        # Check if duplicate prompt is needed
        if existing_hits and not st.session_state.get("confirm_replace_doc"):
            st.warning(f"⚠️ Document **'{file_stem}'** already exists in the vector store ({len(existing_hits)} chunks).")
            col_yes, col_no = st.columns([1, 4])
            with col_yes:
                if st.button("Replace Document", key="confirm_replace_btn", type="primary"):
                    st.session_state["confirm_replace_doc"] = True
                    st.rerun()
            with col_no:
                if st.button("Cancel Upload", key="cancel_upload_btn"):
                    st.session_state["confirm_replace_doc"] = False
                    st.rerun()
        else:
            if st.button("Process & Ingest File", key="process_ingest_btn", type="primary") or st.session_state.get("confirm_replace_doc"):
                st.session_state["confirm_replace_doc"] = False
                with st.spinner("Ingesting file, splitting chunks, and computing embeddings..."):
                    # 1. Save uploaded file to target corpus directory
                    target_dir = CORPUS_DIR / target_source_type
                    target_dir.mkdir(parents=True, exist_ok=True)
                    target_file_path = target_dir / uploaded_file.name
                    target_file_path.write_bytes(uploaded_file.getbuffer())

                    # 2. If replacing existing doc, delete old chunks from vector store first
                    if existing_hits:
                        delete_by_document_name(file_stem)

                    # 3. Dispatch to appropriate loader
                    suffix = target_file_path.suffix.lower()
                    if suffix == ".md":
                        raw_docs = [load_markdown(target_file_path, target_source_type)]
                    elif suffix == ".pdf":
                        raw_docs = [load_pdf(target_file_path, target_source_type)]
                    elif suffix == ".json":
                        raw_docs = load_json(target_file_path, target_source_type)
                    else:
                        st.error(f"Unsupported file format: {suffix}")
                        return

                    # 4. Chunk & embed
                    chunks = chunk_all(raw_docs)
                    if not chunks:
                        st.warning("No text chunks generated from uploaded file.")
                        return

                    texts = [c["text"] for c in chunks]
                    embeddings = embed_texts(texts)
                    add_chunks(chunks, embeddings, batch_size=100)

                st.success(f"Successfully ingested **{uploaded_file.name}** ({len(chunks)} chunks indexed).")
                st.rerun()

    st.markdown("---")

    # Document Deletion section
    st.markdown("#### 🗑️ Delete Document")
    if not docs_metadata:
        st.info("No documents available to delete.")
        return

    doc_names_list = sorted([d["document_name"] for d in docs_metadata])
    selected_doc_to_delete = st.selectbox(
        "Select Document to Delete",
        options=doc_names_list,
        key="doc_delete_selectbox",
    )

    doc_info = next((d for d in docs_metadata if d["document_name"] == selected_doc_to_delete), None)
    if doc_info:
        st.write(f"Selected: **{doc_info['document_name']}** (`{doc_info['chunk_count']}` chunks, source: `{doc_info['source_path']}`)")

        if st.session_state.get("pending_delete_doc") != selected_doc_to_delete:
            if st.button("Delete Document", key="initiate_delete_btn"):
                st.session_state["pending_delete_doc"] = selected_doc_to_delete
                st.rerun()
        else:
            st.error(f"⚠️ Are you sure you want to permanently delete **'{selected_doc_to_delete}'** from ChromaDB and disk? This action cannot be undone.")
            c1, c2 = st.columns([1, 4])
            with c1:
                if st.button("Confirm Delete", key="confirm_delete_btn", type="primary"):
                    with st.spinner("Deleting document chunks and source file..."):
                        deleted_chunks = delete_by_document_name(selected_doc_to_delete)
                        if doc_info.get("source_path"):
                            _delete_source_file_from_disk(selected_doc_to_delete, doc_info["source_path"])
                    st.session_state.pop("pending_delete_doc", None)
                    st.success(f"Deleted **{selected_doc_to_delete}** ({deleted_chunks} chunks removed).")
                    st.rerun()
            with c2:
                if st.button("Cancel", key="cancel_delete_btn"):
                    st.session_state.pop("pending_delete_doc", None)
                    st.rerun()


def render_doc_library() -> None:
    """Main rendering entry point for Document Library tab."""
    docs_metadata = get_all_documents_metadata()

    browse_tab, manage_tab = st.tabs(["Browse Documents", "Manage Documents"])

    with browse_tab:
        render_browse_view(docs_metadata)

    with manage_tab:
        render_manage_view(docs_metadata)
