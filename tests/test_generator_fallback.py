"""
Unit test for generator.py LLM output fallback mechanism.
Verifies that unformatted/raw LLM output is handled gracefully without crashing.
"""

from unittest.mock import patch
from generation.generator import generate_answer, parse_severity_from_answer


def test_generator_fallback_on_unformatted_llm_response():
    sample_chunks = [
        {
            "text": "[A05_2025-Injection] [How to prevent]\nUse parameterized queries.",
            "metadata": {
                "document_name": "A05_2025-Injection",
                "source_path": "data/corpus/owasp_top10/A05_2025-Injection.md",
                "source_type": "owasp_top10",
                "severity": "critical",
            },
        }
    ]

    raw_unformatted_llm_output = (
        "To prevent SQL injection, you should always use parameterized queries or prepared statements. "
        "Do not concatenate user input directly into SQL strings."
    )

    with patch("generation.generator.call_llm", return_value=raw_unformatted_llm_output):
        result = generate_answer("How do I prevent SQL injection?", sample_chunks)

        # 1. Confirm answer text is preserved verbatim without crashing
        assert result["answer"] == raw_unformatted_llm_output, "Raw text should be preserved verbatim."

        # 2. Confirm fallback severity is derived cleanly from chunk metadata
        assert result["severity"] == "Critical", f"Expected fallback severity 'Critical', got '{result['severity']}'."

        # 3. Confirm sources are still populated
        assert len(result["sources"]) == 1
        assert result["sources"][0]["document_name"] == "A05_2025-Injection"


def test_parse_severity_from_answer_fallback():
    # When Severity header is missing, return default_severity fallback
    unformatted_text = "Just plain advice without any headers."
    assert parse_severity_from_answer(unformatted_text, default_severity="High") == "High"
    assert parse_severity_from_answer(unformatted_text, default_severity="Critical") == "Critical"

    # When Severity header IS present, parse it
    formatted_text = "Severity: Medium\nSummary: Example summary."
    assert parse_severity_from_answer(formatted_text, default_severity="High") == "Medium"
