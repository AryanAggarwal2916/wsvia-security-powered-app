"""
Code Snippet Analyser tab — WSVIA stretch goal.

Renders inside the 'Code Snippet Analyser' tab wired from ui/app.py.
Accepts a pasted code snippet, retrieves OWASP/WSTG reference context,
calls analyse_code_snippet(), and displays structured findings.

The mandatory disclaimer is ALWAYS visible at the top of the results
panel — it is never hidden inside a collapsible element.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import streamlit as st

_PROJECT_ROOT = Path(__file__).parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from retrieval.retriever import retrieve  # noqa: E402
from generation.generator import analyse_code_snippet  # noqa: E402

logger = logging.getLogger(__name__)

# Mandatory disclaimer text — must always be visible, never collapsed.
_DISCLAIMER = (
    "**DISCLAIMER:** This analysis is AI-generated and provided for "
    "educational/informational purposes **only**. It is **not** a substitute "
    "for a professional security audit or penetration test. Always have critical "
    "code reviewed by a qualified security engineer before production deployment."
)

# Matches the severity palette in ui/app.py for visual consistency across tabs.
RISK_COLOURS: dict[str, str] = {
    "critical": "#FF5C5C",
    "high": "#FF9F45",
    "medium": "#F2CB4E",
    "low": "#4ADE80",
}

RISK_TEXT_ON: dict[str, str] = {
    "critical": "#E8F5EA",
    "high": "#E8F5EA",
    "medium": "#E8F5EA",
    "low": "#E8F5EA",
}

LANGUAGE_OPTIONS: list[str] = [
    "Auto-detect",
    "Python",
    "JavaScript / TypeScript",
    "Java",
    "PHP",
    "Go",
    "C / C++",
    "Ruby",
    "SQL",
    "Shell / Bash",
    "Other",
]


def _risk_banner(risk_level: str) -> None:
    """Render a terminal-framed risk-level banner with bracket-tag style."""
    key = risk_level.lower()
    colour = RISK_COLOURS.get(key, "#6B8F72")
    st.markdown(
        f'''
        <div class="wsvia-risk-banner" style="color:{colour};
        border: 1px solid {colour};">
        :: RISK LEVEL: {risk_level.upper()} ::
        </div>
        ''',
        unsafe_allow_html=True,
    )


def _render_reference_cards(sources: list[dict]) -> None:
    """Render reference documents as monospace log-row list matching the chat tab style."""
    rows_html = ['<div class="wsvia-source-stack">']
    for i, meta in enumerate(sources, 1):
        doc = meta.get("document_name", "unknown")
        path = meta.get("source_path", "")
        heading = meta.get("heading", "")
        owasp = meta.get("owasp_id", "")
        wstg = meta.get("wstg_id", "")
        sev = (meta.get("severity") or "").capitalize()
        colour = RISK_COLOURS.get(sev.lower(), "#5EEAD4")

        tags = []
        if owasp:
            tags.append(f"OWASP {owasp}")
        if wstg:
            tags.append(f"WSTG {wstg}")
        tags_html = " / ".join(tags)

        sev_tag = (
            f'<span class="wsvia-source-sev" style="color:{colour};'
            f'border-color:{colour};">[{sev.upper()}]</span>'
        ) if sev and sev.lower() in RISK_COLOURS else ""

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


def _render_analysis_result(result: dict) -> None:
    """Render the structured output from analyse_code_snippet()."""
    analysis: str = result.get("analysis", "")
    sources: list[dict] = result.get("sources", [])

    # --- Always-visible disclaimer banner (never collapsible) -------------
    st.error(_DISCLAIMER)

    # --- Parse and render the structured LLM output -----------------------
    import re

    risk_match = re.search(
        r"summary risk level[:\s]+([A-Za-z]+)", analysis, re.IGNORECASE
    )
    if risk_match:
        risk_level = risk_match.group(1)
        _risk_banner(risk_level)

    st.markdown(analysis)

    # --- Reference sources ------------------------------------------------
    if sources:
        with st.expander(f":: Reference Documents ({len(sources)})", expanded=False):
            _render_reference_cards(sources)


def render() -> None:
    """Main entry point wired from ui/app.py."""

    st.subheader("Code Snippet Analyser")
    st.markdown(
        "Paste a code snippet below to receive a security review grounded in "
        "OWASP Top 10 and WSTG reference documentation. Findings are mapped to "
        "OWASP categories where applicable."
    )

    # Language selector (informational — helps the user frame the question)
    col_lang, col_spacer = st.columns([2, 5])
    with col_lang:
        language = st.selectbox(
            "Language (optional)",
            options=LANGUAGE_OPTIONS,
            key="analyser_language",
            help="Helps label the code block — does not affect the analysis.",
        )

    # Code input
    code_snippet: str = st.text_area(
        "Paste your code here",
        height=280,
        key="analyser_code_input",
        placeholder=(
            "# Example:\ndef login(username, password):\n"
            "    query = f\"SELECT * FROM users WHERE username='{username}'\"\n"
            "    ..."
        ),
    )

    # Top-k control
    top_k: int = st.slider(
        "Reference chunks to retrieve",
        min_value=3,
        max_value=10,
        value=5,
        key="analyser_top_k",
        help="More chunks = more context, but slower response.",
    )

    analyse_btn = st.button(
        "Analyse Code",
        key="analyse_btn",
        type="primary",
        use_container_width=False,
    )

    if not analyse_btn:
        return

    if not code_snippet or not code_snippet.strip():
        st.warning("Please paste a code snippet before clicking Analyse.")
        return

    # Build a retrieval query from the snippet + language hint
    lang_hint = "" if language == "Auto-detect" else f"{language} "
    snippet_sample = code_snippet.strip()[:1000]
    retrieval_query = f"Code security vulnerability review {lang_hint}:\n{snippet_sample}"

    with st.spinner("Retrieving OWASP reference context..."):
        try:
            chunks = retrieve(retrieval_query, top_k=top_k)
        except Exception as exc:
            logger.exception("Retrieval failed during code analysis: %s", exc)
            st.error(f"Retrieval error: {exc}")
            return

    with st.spinner("Analysing code snippet..."):
        try:
            result = analyse_code_snippet(code_snippet, chunks)
        except Exception as exc:
            logger.exception("Code analysis failed: %s", exc)
            st.error(f"Analysis error: {exc}")
            return

    st.markdown("---")
    _render_analysis_result(result)