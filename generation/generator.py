"""
Generation layer orchestration: retrieved chunks + chat history -> LLM -> answer.
"""

import logging
import re
from typing import Any

from config import MAX_CHAT_HISTORY_TURNS
from generation.llm_client import call_llm
from generation.prompts import build_code_analysis_prompt, build_qa_prompt
MIN_RELEVANT_DISTANCE = 1.05  # tune against your corpus; anything past this = noise, not a match

logger = logging.getLogger(__name__)


def format_context(chunks: list[dict[str, Any]]) -> str:
    """Turn retrieved chunks into a context string with source markers."""
    if not chunks:
        return "No relevant security documentation found."

    formatted_parts = []
    for c in chunks:
        meta = c.get("metadata", {})
        doc_name = meta.get("document_name", "unknown")
        source_path = meta.get("source_path", "unknown")
        severity = meta.get("severity", "n/a")
        heading = meta.get("heading", "")

        header = f"[source: {doc_name} | {source_path}] (severity: {severity})"
        if heading:
            header += f" [section: {heading}]"

        text = c.get("text", "").strip()
        formatted_parts.append(f"{header}\n{text}")

    return "\n\n---\n\n".join(formatted_parts)


def format_chat_history(history: list[dict[str, str]] | None) -> str:
    """Turn a list of {"role": "user"/"assistant", "content": str} into a flat string."""
    if not history:
        return "None"

    recent = history[-(MAX_CHAT_HISTORY_TURNS * 2) :]
    lines = []
    for msg in recent:
        role = msg.get("role", "user").capitalize()
        content = msg.get("content", "").strip()
        lines.append(f"{role}: {content}")

    return "\n".join(lines)


def parse_severity_from_answer(answer_text: str, default_severity: str = "High") -> str:
    """Extract severity tag from LLM output if present."""
    m = re.search(r"Severity:\s*(Critical|High|Medium|Low|Informational)", answer_text, re.IGNORECASE)
    if m:
        return m.group(1).capitalize()
    return default_severity


def clean_fabricated_citations(answer_text: str, chunks: list[dict[str, Any]]) -> str:
    """Post-generation validation: filter out external URLs or citation lines not in corpus context."""
    if not answer_text or not chunks:
        return answer_text

    context_text = "\n".join([c.get("text", "") for c in chunks])
    allowed_sources = set()
    for c in chunks:
        meta = c.get("metadata", {})
        if meta.get("document_name"):
            allowed_sources.add(meta.get("document_name").lower())
        if meta.get("source_path"):
            allowed_sources.add(meta.get("source_path").lower())

    url_pattern = re.compile(r'https?://[^\s\)\>\]]+')

    def sanitize_url(match: re.Match) -> str:
        url = match.group(0)
        clean_url = url.rstrip('.,;:')
        if clean_url in context_text:
            return url
        return "[external link removed]"

    cleaned_text = url_pattern.sub(sanitize_url, answer_text)

    lines = cleaned_text.split("\n")
    cleaned_lines = []
    in_sources = False
    for line in lines:
        if re.match(r'^(Sources|Reference Sources)[:\s]*', line, re.IGNORECASE):
            in_sources = True
            cleaned_lines.append(line)
            continue

        if in_sources:
            line_str = line.strip()
            if line_str.startswith(("*", "-", "1.", "2.", "3.", "4.", "5.")):
                if "[external link removed]" in line:
                    if not any(src in line.lower() for src in allowed_sources):
                        continue
                    else:
                        line = line.replace("[external link removed]", "").rstrip(" :-")
            elif line_str != "" and not line_str.startswith(("*", "-", "1.", "2.", "3.", "4.", "5.")):
                in_sources = False

        cleaned_lines.append(line)

    return "\n".join(cleaned_lines)


def generate_answer(
    question: str,
    chunks: list[dict[str, Any]],
    chat_history: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Full Layer 4 pipeline: format context -> call LLM -> return structured answer.

    Fallback mechanism: if LLM output does not match expected headers, raw text is rendered.
    """
    relevant_chunks = [c for c in chunks if c.get("distance", 0.0) < MIN_RELEVANT_DISTANCE]

    if not relevant_chunks:
        return {
            "answer": (
                "I don't have information about this in the vulnerability corpus. "
                "This may be outside the scope of the current knowledge base."
            ),
            "severity": "Unknown",
            "sources": [],
            "chunks": [],
        }

    context_str = format_context(relevant_chunks)
    history_str = format_chat_history(chat_history)

    prompt = build_qa_prompt(context_str, history_str, question)
    raw_answer = call_llm(prompt)
    cleaned_answer = clean_fabricated_citations(raw_answer, relevant_chunks)

    # Determine fallback severity from chunks
    chunk_severities = [c.get("metadata", {}).get("severity", "").lower() for c in relevant_chunks if c.get("metadata")]
    top_sev = "High"
    if "critical" in chunk_severities:
        top_sev = "Critical"
    elif "high" in chunk_severities:
        top_sev = "High"
    elif "medium" in chunk_severities:
        top_sev = "Medium"
    elif "low" in chunk_severities:
        top_sev = "Low"

    inferred_severity = parse_severity_from_answer(cleaned_answer, default_severity=top_sev)

    # Extract unique source metadata
    sources = []
    seen_paths = set()
    for c in relevant_chunks:
        meta = c.get("metadata", {})
        path = meta.get("source_path")
        if path and path not in seen_paths:
            seen_paths.add(path)
            sources.append(meta)

    return {
        "answer": cleaned_answer,
        "severity": inferred_severity,
        "sources": sources,
        "chunks": relevant_chunks,
    }


def analyse_code_snippet(code_snippet: str, chunks: list[dict[str, Any]]) -> dict[str, Any]:
    """Code snippet security review analyser."""
    context_str = format_context(chunks)
    prompt = build_code_analysis_prompt(code_snippet, context_str)
    raw_answer = call_llm(prompt)
    cleaned_answer = clean_fabricated_citations(raw_answer, chunks)

    disclaimer = (
        "This analysis is AI-generated and provided for educational/informational purposes only. "
        "It is not a substitute for a professional security audit or penetration test. "
        "Always have critical code reviewed by a qualified security engineer before production deployment."
    )

    if disclaimer.strip() not in cleaned_answer:
        cleaned_answer = f"{cleaned_answer.strip()}\n\n---\nDISCLAIMER:\n{disclaimer}"

    sources = [c.get("metadata", {}) for c in chunks if c.get("metadata")]

    return {
        "analysis": cleaned_answer,
        "sources": sources,
        "chunks": chunks,
    }
