"""
Streamlit entry point — WSVIA Web Security & Vulnerability Intelligence Assistant.

Architecture:
  Layer 3  retrieval.retriever.retrieve()
  Layer 4  generation.generator.generate_answer()

The indexing pipeline (build_index.py) must be run offline before launching
this UI.  This module never imports from ingestion/ or indexing/ directly.

Run with:
    cd wsvia
    streamlit run ui/app.py
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Make the project root importable when running via `streamlit run ui/app.py`
# from inside the wsvia/ package directory.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

load_dotenv(_PROJECT_ROOT / ".env")
load_dotenv()

from config import MAX_CHAT_HISTORY_TURNS, SOURCE_TYPES, DEFAULT_TOP_K  # noqa: E402
from retrieval.retriever import retrieve, get_related_vulnerabilities  # noqa: E402
from generation.generator import generate_answer  # noqa: E402
from ui.code_analyser import render as render_code_analyser  # noqa: E402
from ui.doc_library import render_doc_library  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants / options
# ---------------------------------------------------------------------------
SOURCE_TYPE_OPTIONS: list[str] = ["All"] + list(SOURCE_TYPES)

# Severity palette — semantic (red=critical through green=low).
SEVERITY_COLOURS: dict[str, str] = {
    "critical": "#FF5C5C",
    "high": "#FF9F45",
    "medium": "#F2CB4E",
    "low": "#4ADE80",
    "informational": "#5EEAD4",
}

# Text colour for bracket-tag badges — the badge text IS the severity colour,
# so this is kept only for backward API compat; not used for filled backgrounds.
SEVERITY_TEXT_ON: dict[str, str] = {
    "critical": "#E8F5EA",
    "high": "#E8F5EA",
    "medium": "#E8F5EA",
    "low": "#E8F5EA",
    "informational": "#E8F5EA",
}


# ---------------------------------------------------------------------------
# Session state helpers
# ---------------------------------------------------------------------------

def init_session_state() -> None:
    """Initialise all required session_state keys (idempotent)."""
    st.session_state.setdefault("chat_history", [])   # list[{"role", "content"}]
    st.session_state.setdefault("source_filter", "All")


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _severity_badge(severity: str) -> str:
    """Return an HTML bracket-tag for the given severity string — terminal style."""
    key = severity.lower()
    colour = SEVERITY_COLOURS.get(key, "#6B8F72")
    return (
        f'<span class="wsvia-badge" style="color:{colour};'
        f'border-color:{colour};">[{severity.upper()}]</span>'
    )


def _render_sources_expander(sources: list[dict]) -> None:
    """Render a collapsible Sources section — monospace log-row list."""
    if not sources:
        return
    with st.expander(f":: Sources ({len(sources)})", expanded=False):
        rows_html = ['<div class="wsvia-source-stack">']
        for i, meta in enumerate(sources, 1):
            doc = meta.get("document_name", "unknown")
            path = meta.get("source_path", "")
            sev = meta.get("severity", "n/a").capitalize()
            sev_key = sev.lower()
            colour = SEVERITY_COLOURS.get(sev_key, "#6B8F72")
            owasp = meta.get("owasp_id", "")
            wstg = meta.get("wstg_id", "")
            heading = meta.get("heading", "")

            tags = []
            if owasp:
                tags.append(f"OWASP {owasp}")
            if wstg:
                tags.append(f"WSTG {wstg}")
            tags_html = " / ".join(tags)

            sev_tag = (
                f'<span class="wsvia-source-sev" style="color:{colour};'
                f'border-color:{colour};">[{sev.upper()}]</span>'
            ) if sev_key in SEVERITY_COLOURS else ""

            rows_html.append(
                f'''
                <div class="wsvia-source-row" style="--accent:{colour};">
                    <div class="wsvia-source-row-top">
                        <span class="wsvia-source-index">{i:02d}</span>
                        <span class="wsvia-source-doc">{doc}</span>
                        {sev_tag}
                    </div>
                    {f'<div class="wsvia-source-heading">{heading}</div>' if heading else ''}
                    {f'<div class="wsvia-source-path"><code>{path}</code></div>' if path else ''}
                    {f'<div class="wsvia-source-tags">{tags_html}</div>' if tags_html else ''}
                </div>
                '''
            )
        rows_html.append("</div>")
        st.markdown("".join(rows_html), unsafe_allow_html=True)


def _render_assistant_message(result: dict) -> None:
    """Render one assistant turn: severity bracket tag + answer markdown + sources."""
    severity: str = result.get("severity", "High")
    answer: str = result.get("answer", "")
    sources: list[dict] = result.get("sources", [])

    with st.chat_message("assistant"):
        # Severity bracket tag always visible, never collapsible
        st.markdown(_severity_badge(severity), unsafe_allow_html=True)
        st.markdown("")            # visual spacer
        st.markdown(answer)
        _render_sources_expander(sources)


def _render_related_suggestions(suggestions: list[dict], key_prefix: str) -> None:
    """Render 2-3 related vulnerability/topic buttons below assistant answer."""
    if not suggestions:
        return
    st.markdown(
        '<div style="margin-top: 10px; margin-bottom: 6px; font-size: 0.8rem; '
        'color: var(--wsvia-accent); font-weight: 700; letter-spacing: 0.05em;">'
        '🔍 RELATED TOPICS & VULNERABILITIES:</div>',
        unsafe_allow_html=True,
    )
    cols = st.columns(len(suggestions))
    for idx, sug in enumerate(suggestions):
        doc = sug.get("doc", "")
        heading = sug.get("heading", "")
        btn_label = f"{doc}: {heading[:25]}" if heading and heading != doc else doc
        if not btn_label:
            btn_label = f"Topic {idx+1}"
        with cols[idx]:
            if st.button(f"📌 {btn_label}", key=f"sug_{key_prefix}_{idx}_{abs(hash(btn_label))}", use_container_width=True):
                st.session_state["pending_query"] = sug.get("query", btn_label)
                st.rerun()


# ---------------------------------------------------------------------------
# Chat tab
# ---------------------------------------------------------------------------

def render_chat_tab() -> None:
    """Main Security Q&A tab."""

    # --- Sidebar controls (scoped visually to this tab) -------------------
    with st.sidebar:
        st.markdown("## Search Options")
        source_filter: str = st.selectbox(
            "Filter by source type",
            options=SOURCE_TYPE_OPTIONS,
            index=SOURCE_TYPE_OPTIONS.index(st.session_state.source_filter),
            key="source_filter_select",
            help=(
                "Restrict retrieval to a specific corpus folder. "
                "'All' searches across every loaded source type."
            ),
        )
        st.session_state.source_filter = source_filter

        top_k: int = st.slider(
            "Results to retrieve (top-k)",
            min_value=1,
            max_value=10,
            value=DEFAULT_TOP_K,
            key="top_k_slider",
        )

        st.markdown("---")
        st.caption(
            f"Multi-turn context: last **{MAX_CHAT_HISTORY_TURNS}** turns · "
            f"Model: `llama-3.1-8b-instant`"
        )

        if st.button("Clear conversation", key="clear_chat_btn", use_container_width=True):
            st.session_state.chat_history = []
            st.rerun()

    # --- Replay existing history ------------------------------------------
    for idx, msg in enumerate(st.session_state.chat_history):
        if msg["role"] == "user":
            with st.chat_message("user"):
                st.markdown(msg["content"])
        else:
            # stored as dict with answer/severity/sources
            _render_assistant_message(msg["result"])
            if msg["result"].get("related_suggestions"):
                _render_related_suggestions(msg["result"]["related_suggestions"], key_prefix=f"hist_{idx}")

    # --- New question input -----------------------------------------------
    pending_q = st.session_state.pop("pending_query", None)
    chat_input_q: str | None = st.chat_input(
        "Ask a security question… e.g. 'How do I prevent SQL injection?'"
    )

    question: str | None = pending_q if pending_q else chat_input_q

    if not question:
        return

    # Immediately echo the user turn
    with st.chat_message("user"):
        st.markdown(question)

    # Build trimmed history for the LLM (last MAX_CHAT_HISTORY_TURNS exchanges)
    lm_history: list[dict[str, str]] = []
    for msg in st.session_state.chat_history[-(MAX_CHAT_HISTORY_TURNS * 2):]:
        if msg["role"] == "user":
            lm_history.append({"role": "user", "content": msg["content"]})
        else:
            lm_history.append({"role": "assistant", "content": msg["result"]["answer"]})

    # Resolve source filter
    active_filter = source_filter if source_filter != "All" else None

    # Multi-turn retrieval query enhancement: if follow-up query is referential, retain topic context
    retrieval_query = question
    if lm_history:
        last_user_msgs = [m["content"] for m in lm_history if m["role"] == "user"]
        if last_user_msgs and (len(question.split()) <= 6 or any(w in question.lower() for w in ["it", "that", "this", "remediate", "fix"])):
            retrieval_query = f"{last_user_msgs[-1]} {question}"

    with st.spinner("Retrieving relevant security context..."):
        try:
            chunks = retrieve(retrieval_query, top_k=top_k, source_type_filter=active_filter)
        except Exception as exc:
            logger.exception("Retrieval failed: %s", exc)
            st.error(f"Retrieval error: {exc}")
            return

    # If no chunks were found for the given filter, tell the user clearly
    if not chunks:
        no_ctx_result = {
            "answer": (
                "**No relevant security documentation found for your question.**\n\n"
                + (
                    f"The `{source_filter}` corpus folder has not been indexed yet "
                    f"or contains no content matching your query. "
                    if active_filter
                    else "The corpus may be empty or not yet indexed. "
                )
                + "Please check that `build_index.py` has been run and the relevant "
                "source folders exist under `data/corpus/`."
            ),
            "severity": "Informational",
            "sources": [],
        }
        _render_assistant_message(no_ctx_result)
        st.session_state.chat_history.append({"role": "user", "content": question})
        st.session_state.chat_history.append({"role": "assistant", "result": no_ctx_result})
        return

    with st.spinner("Generating answer..."):
        try:
            result = generate_answer(question, chunks, chat_history=lm_history)
        except Exception as exc:
            logger.exception("Generation failed: %s", exc)
            st.error(f"Generation error: {exc}")
            return

    # Wire in get_related_vulnerabilities using top chunk's metadata
    suggestions = []
    if chunks and chunks[0].get("metadata"):
        top_meta = chunks[0]["metadata"]
        try:
            related_hits = get_related_vulnerabilities(top_meta, top_k=3)
            seen_queries = set()
            for rh in related_hits:
                rmeta = rh.get("metadata", {})
                rdoc = rmeta.get("document_name", "")
                rhead = rmeta.get("heading", "")
                rquery = rdoc
                if rhead and rhead.lower() != rdoc.lower():
                    rquery = f"{rdoc} {rhead}"
                if rquery and rquery not in seen_queries and rdoc != top_meta.get("document_name"):
                    seen_queries.add(rquery)
                    suggestions.append({"doc": rdoc, "heading": rhead, "query": rquery})
                if len(suggestions) >= 3:
                    break
        except Exception as e:
            logger.warning(f"Failed to fetch related vulnerabilities: {e}")

    result["related_suggestions"] = suggestions

    _render_assistant_message(result)
    if suggestions:
        _render_related_suggestions(suggestions, key_prefix="latest")

    # Persist both turns to history
    st.session_state.chat_history.append({"role": "user", "content": question})
    st.session_state.chat_history.append({"role": "assistant", "result": result})



# ---------------------------------------------------------------------------
# Theme CSS
# ---------------------------------------------------------------------------

_THEME_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap');

:root {
    --wsvia-bg: #060B08;
    --wsvia-bg-elevated: #0C120E;
    --wsvia-panel: #0C120E;
    --wsvia-panel-border: rgba(57, 255, 136, 0.14);
    --wsvia-border-dim: rgba(57, 255, 136, 0.14);
    --wsvia-accent: #39FF88;
    --wsvia-accent-dim: rgba(57, 255, 136, 0.25);
    --wsvia-text: #E8F5EA;
    --wsvia-text-dim: #6B8F72;
}

/* ---- keyframes ---- */
@keyframes wsvia-ping {
    0%   { transform: scale(1);   opacity: 0.6; }
    75%  { transform: scale(3.2); opacity: 0; }
    100% { transform: scale(3.2); opacity: 0; }
}
@keyframes wsvia-sweep {
    0%   { top: -120px; }
    100% { top: 100vh; }
}
@keyframes wsvia-radar-spin {
    from { transform: rotate(0deg); }
    to   { transform: rotate(360deg); }
}

/* ---- base canvas + CRT scanline texture ---- */
[data-testid="stAppViewContainer"] {
    position: relative;
    background:
        repeating-linear-gradient(
            0deg,
            transparent,
            transparent 2px,
            rgba(57, 255, 136, 0.015) 2px,
            rgba(57, 255, 136, 0.015) 4px
        ),
        var(--wsvia-bg);
}
/* ---- animated scanline sweep band ---- */
[data-testid="stAppViewContainer"]::before {
    content: "";
    position: fixed;
    left: 0;
    right: 0;
    height: 120px;
    background: linear-gradient(
        180deg,
        transparent,
        rgba(57, 255, 136, 0.035),
        transparent
    );
    pointer-events: none;
    z-index: 0;
    animation: wsvia-sweep 7s linear infinite;
}
[data-testid="stHeader"] { background: transparent; }

html, body, [class*="css"] {
    font-family: 'JetBrains Mono', 'Consolas', monospace !important;
    color: var(--wsvia-text);
}

h1, h2, h3, h4, h5, h6 {
    font-family: 'JetBrains Mono', 'Consolas', monospace !important;
}

code, pre, [data-testid="stCaptionContainer"] {
    font-family: 'JetBrains Mono', 'Consolas', monospace !important;
}

/* ---- SCAN ACTIVE eyebrow ---- */
.wsvia-eyebrow {
    position: relative;
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    color: var(--wsvia-accent);
    margin-bottom: 4px;
    text-transform: uppercase;
}
/* sonar ping dot */
.wsvia-eyebrow .wsvia-ping {
    position: relative;
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--wsvia-accent);
    margin-left: 6px;
    vertical-align: middle;
}
.wsvia-eyebrow .wsvia-ping::before {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: 50%;
    background: var(--wsvia-accent);
    animation: wsvia-ping 1.8s cubic-bezier(0, 0, 0.2, 1) infinite;
}
/* rotating radar sweep wedge */
.wsvia-eyebrow::after {
    content: "";
    position: absolute;
    top: -6px;
    left: -10px;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: conic-gradient(
        from 0deg,
        rgba(57, 255, 136, 0.25),
        transparent 60deg
    );
    animation: wsvia-radar-spin 3s linear infinite;
    opacity: 0.5;
    pointer-events: none;
    z-index: -1;
}

/* ---- hero title block ---- */
h1 {
    font-weight: 700 !important;
    letter-spacing: -0.01em;
    color: var(--wsvia-text) !important;
}
[data-testid="stAppViewContainer"] > .main .block-container > div:first-child {
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--wsvia-panel-border);
    margin-bottom: 1.2rem;
}

/* ---- sidebar: flat panel, no blur ---- */
section[data-testid="stSidebar"] {
    background: var(--wsvia-panel);
    border-right: 1px solid var(--wsvia-panel-border);
}
section[data-testid="stSidebar"] .stMarkdown h2 {
    font-size: 0.95rem;
    letter-spacing: 0.03em;
    color: var(--wsvia-accent);
    margin-bottom: 0.7rem;
}

/* ---- tabs: underline indicator style ---- */
[data-testid="stTabs"] [data-baseweb="tab-list"] {
    gap: 4px;
    border-bottom: 1px solid var(--wsvia-panel-border);
}
[data-testid="stTabs"] [data-baseweb="tab"] {
    background: transparent;
    color: var(--wsvia-text-dim);
    font-weight: 500;
}
[data-testid="stTabs"] [aria-selected="true"] {
    color: var(--wsvia-accent) !important;
    box-shadow: inset 0 -2px 0 var(--wsvia-accent);
}

/* ---- chat message containers: flat, sharp corners, 3D tilt ---- */
[data-testid="stChatMessage"] {
    background: var(--wsvia-panel);
    border: 1px solid var(--wsvia-panel-border);
    border-radius: 3px;
    padding: 0.9rem 1.1rem !important;
    margin-bottom: 0.9rem;
    transform-style: preserve-3d;
    transition: transform 0.25s ease, border-left-color 0.2s ease;
}
[data-testid="stChatMessage"]:hover {
    transform: perspective(600px) rotateX(1.5deg) rotateY(-1.5deg);
}

/* ---- severity bracket-tag badge ---- */
.wsvia-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 2px;
    border: 1px solid;
    background: transparent;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    font-family: 'JetBrains Mono', monospace;
}

/* ---- source evidence: monospace log-row list ---- */
.wsvia-source-stack {
    display: flex;
    flex-direction: column;
    gap: 0;
    padding-top: 4px;
}
.wsvia-source-row {
    position: relative;
    background: transparent;
    border-bottom: 1px solid rgba(255,255,255,0.06);
    border-left: 2px solid var(--accent);
    padding: 10px 14px;
    transform-style: preserve-3d;
    transition: transform 0.2s ease, background 0.15s ease, border-left-width 0.15s ease;
}
.wsvia-source-row:last-child {
    border-bottom: none;
}
.wsvia-source-row:hover {
    border-left-width: 4px;
    transform: perspective(500px) rotateX(2deg) translateZ(2px);
}
.wsvia-source-row-top {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.85rem;
}
.wsvia-source-index {
    font-family: 'JetBrains Mono', monospace;
    color: var(--wsvia-text-dim);
    font-size: 0.75rem;
}
.wsvia-source-doc {
    font-weight: 600;
    color: var(--wsvia-text);
    flex-grow: 1;
}
.wsvia-source-sev {
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
    border: 1px solid;
    padding: 1px 5px;
    border-radius: 2px;
    background: transparent;
}
.wsvia-source-heading {
    font-size: 0.8rem;
    color: var(--wsvia-text-dim);
    margin-top: 3px;
}
.wsvia-source-path {
    margin-top: 5px;
    font-size: 0.74rem;
    color: var(--wsvia-text-dim);
    opacity: 0.8;
}
.wsvia-source-tags {
    margin-top: 5px;
    font-size: 0.74rem;
    color: var(--wsvia-accent);
    opacity: 0.85;
}

/* ---- expander ("Sources" / "Reference Documents") ---- */
[data-testid="stExpander"] {
    background: transparent;
    border: 1px solid var(--wsvia-panel-border);
    border-radius: 3px;
}

/* ---- buttons: transparent, hairline border ---- */
[data-testid="stButton"] button {
    background: transparent;
    border: 1px solid var(--wsvia-accent-dim);
    color: var(--wsvia-accent);
    font-weight: 600;
    border-radius: 3px;
    transition: background 0.15s ease;
}
[data-testid="stButton"] button:hover {
    background: rgba(57, 255, 136, 0.08);
    border-color: var(--wsvia-accent);
}

/* ---- slider ---- */
[data-testid="stSlider"] [role="slider"] {
    background-color: var(--wsvia-accent) !important;
}
[data-testid="stSlider"] > div > div > div > div {
    background: var(--wsvia-accent) !important;
}

/* ---- selectbox ---- */
[data-testid="stSelectbox"] > div > div {
    background: var(--wsvia-bg-elevated);
    border: 1px solid var(--wsvia-panel-border);
    border-radius: 3px;
}
[data-testid="stSelectbox"] > div > div:focus-within {
    border-color: var(--wsvia-accent);
    box-shadow: 0 0 0 2px var(--wsvia-accent);
}

/* ---- chat input ---- */
[data-testid="stChatInput"],
[data-testid="stChatInput"] * {
    outline: none !important;
}
[data-testid="stChatInput"] {
    background: var(--wsvia-panel);
    border: 1px solid var(--wsvia-border-dim) !important;
    border-radius: 4px;
    box-shadow: none !important;
}
[data-testid="stChatInput"]:focus-within {
    border-color: var(--wsvia-accent) !important;
    box-shadow: 0 0 0 2px rgba(57, 255, 136, 0.14) !important;
}

/* ---- text area (code input) ---- */
[data-testid="stTextArea"] textarea {
    background: var(--wsvia-bg-elevated) !important;
    color: var(--wsvia-text) !important;
    border: 1px solid var(--wsvia-panel-border) !important;
    border-radius: 3px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.85rem !important;
}
[data-testid="stTextArea"] textarea:focus {
    border-color: var(--wsvia-accent) !important;
    box-shadow: 0 0 0 2px var(--wsvia-accent) !important;
}

/* ---- alerts (disclaimer / errors / warnings) ---- */
[data-testid="stAlert"] {
    background: var(--wsvia-panel) !important;
    border-radius: 3px;
    border: 1px solid var(--wsvia-panel-border);
}

/* ---- primary button (Analyse Code) ---- */
[data-testid="stButton"] button[kind="primary"] {
    background: var(--wsvia-accent) !important;
    color: #060B08 !important;
    border: none !important;
    font-weight: 700 !important;
}
[data-testid="stButton"] button[kind="primary"]:hover {
    background: #2ee077 !important;
}

/* ---- risk banner: terminal-framed ---- */
.wsvia-risk-banner {
    padding: 10px 18px;
    border-radius: 3px;
    font-weight: 700;
    font-size: 0.95rem;
    margin-bottom: 1rem;
    letter-spacing: 0.06em;
    background: transparent;
    font-family: 'JetBrains Mono', monospace;
}
/* ---- fixed background scene, sits behind all content ---- */
.wsvia-bg-scene {
    position: fixed;
    inset: 0;
    z-index: 0;
    overflow: hidden;
    pointer-events: none;
}

/* Ensure actual app content stacks above the background scene */
[data-testid="stAppViewContainer"] > .main {
    position: relative;
    z-index: 1;
}
section[data-testid="stSidebar"] {
    position: relative;
    z-index: 1;
}

/* Concentric radar rings, centered, huge, crisp ring outlines */
.wsvia-radar-rings {
    position: absolute;
    top: 50%;
    left: 50%;
    width: 0;
    height: 0;
}
.wsvia-radar-rings span {
    position: absolute;
    top: 50%;
    left: 50%;
    border: 1px solid rgba(57, 255, 136, 0.14);
    border-radius: 50%;
    transform: translate(-50%, -50%);
}
.wsvia-radar-rings span:nth-child(1) { width: 260px;  height: 260px; }
.wsvia-radar-rings span:nth-child(2) { width: 560px;  height: 560px; }
.wsvia-radar-rings span:nth-child(3) { width: 900px;  height: 900px; }
.wsvia-radar-rings span:nth-child(4) { width: 1300px; height: 1300px; }

/* Full-viewport rotating sweep wedge, centered on the same origin as the rings */
.wsvia-radar-sweep {
    position: absolute;
    top: 50%;
    left: 50%;
    width: 1400px;
    height: 1400px;
    margin: -700px 0 0 -700px;
    border-radius: 50%;
    background: conic-gradient(
        from 0deg,
        transparent 0deg,
        rgba(57, 255, 136, 0.22) 1deg,
        rgba(57, 255, 136, 0.08) 4deg,
        transparent 9deg,
        transparent 360deg
    );
    animation: wsvia-radar-spin-big 6s linear infinite;
    transform-origin: center center;
}
@keyframes wsvia-radar-spin-big {
    from { transform: rotate(0deg); }
    to   { transform: rotate(360deg); }
}

/* 3D perspective grid floor at the bottom of the viewport, scrolling toward viewer */
.wsvia-grid-floor {
    position: absolute;
    bottom: 0;
    left: -20%;
    width: 140%;
    height: 45vh;
    background-image:
        linear-gradient(rgba(57, 255, 136, 0.12) 1px, transparent 1px),
        linear-gradient(90deg, rgba(57, 255, 136, 0.12) 1px, transparent 1px);
    background-size: 48px 48px;
    transform: perspective(400px) rotateX(62deg);
    transform-origin: bottom center;
    animation: wsvia-grid-scroll 2.2s linear infinite;
    -webkit-mask-image: linear-gradient(to top, black 30%, transparent 100%);
    mask-image: linear-gradient(to top, black 30%, transparent 100%);
}
@keyframes wsvia-grid-scroll {
    from { background-position: 0 0, 0 0; }
    to   { background-position: 0 48px, 0 0; }
}

/* Drifting blip dots — simulate live detections appearing on the radar */
.wsvia-blip {
    position: absolute;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--wsvia-accent);
    box-shadow: 0 0 0 0 rgba(57, 255, 136, 0.5);
    animation: wsvia-blip-pulse 5.6s ease-in-out infinite;
    opacity: 0;
}
@keyframes wsvia-blip-pulse {
    0%   { opacity: 0; transform: scale(0.6); box-shadow: 0 0 0 0 rgba(57, 255, 136, 0.5); }
    8%   { opacity: 1; transform: scale(1); }
    20%  { opacity: 1; transform: scale(1); box-shadow: 0 0 0 14px rgba(57, 255, 136, 0); }
    35%  { opacity: 0; transform: scale(0.6); }
    100% { opacity: 0; }
}
</style>
"""


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(
        page_title="WSVIA — Security Intelligence",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.markdown(_THEME_CSS, unsafe_allow_html=True)

    st.markdown(
        '''
        <div class="wsvia-bg-scene">
            <div class="wsvia-radar-rings">
                <span></span><span></span><span></span><span></span>
            </div>
            <div class="wsvia-radar-sweep"></div>
            <div class="wsvia-grid-floor"></div>
            <span class="wsvia-blip" style="top:22%; left:18%; animation-delay:0s;"></span>
            <span class="wsvia-blip" style="top:68%; left:76%; animation-delay:1.4s;"></span>
            <span class="wsvia-blip" style="top:40%; left:85%; animation-delay:2.8s;"></span>
            <span class="wsvia-blip" style="top:78%; left:30%; animation-delay:4.2s;"></span>
        </div>
        ''',
        unsafe_allow_html=True,
    )

    # SCAN ACTIVE eyebrow
    st.markdown(
        '<div class="wsvia-eyebrow">'
        '<span class="wsvia-ping"></span>'
        'SCAN ACTIVE'
        '</div>',
        unsafe_allow_html=True,
    )

    st.title("WSVIA — Web Security & Vulnerability Intelligence Assistant")
    st.caption(
        "RAG-powered security Q&A grounded in OWASP, WSTG, internal audits, and CVE data. "
        "Answers are **cited and severity-tagged** — never speculative."
    )

    init_session_state()

    tab_chat, tab_doc_lib, tab_code = st.tabs(["Security Q&A", "Document Library", "Code Snippet Analyser"])

    with tab_chat:
        render_chat_tab()

    with tab_doc_lib:
        render_doc_library()

    with tab_code:
        render_code_analyser()



if __name__ == "__main__":
    main()