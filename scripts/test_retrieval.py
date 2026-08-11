"""
Test baseline retrieval performance and metadata filtering.
"""

from pathlib import Path
import sys

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from retrieval.retriever import retrieve


QUERIES = [
    ("How do I prevent SQL injection?", ["SQL_Injection_Prevention_Cheat_Sheet.md", "A05_2025-Injection.md"]),
    ("What is broken access control?", ["A01_2025-Broken_Access_Control.md"]),
    ("How to test for reflected XSS?", ["01-Testing_for_Reflected_Cross_Site_Scripting.md"]),
    ("CSRF prevention best practices", ["Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md"]),
    ("Session management security", ["Session_Management_Cheat_Sheet.md", "Testing_for_Session_Management"]),
]


def main():
    print("=" * 80)
    print("STAGE 4 — 5-QUERY RETRIEVAL BASELINE RESULTS")
    print("=" * 80)
    print(f"{'Query':<35} | {'Top-1 Result (document_name)':<40} | {'Status'}")
    print("-" * 85)

    passed_count = 0

    for query_text, expected_keywords in QUERIES:
        results = retrieve(query_text, top_k=5)
        top1_doc = ""
        top1_path = ""
        if results:
            meta = results[0].get("metadata", {})
            top1_doc = meta.get("document_name", "")
            top1_path = meta.get("source_path", "")

        is_match = any(exp.lower() in top1_doc.lower() or exp.lower() in top1_path.lower() for exp in expected_keywords)
        if is_match:
            passed_count += 1
            status = "PASSED"
        else:
            status = f"CHECK (Expected: {', '.join(expected_keywords)})"

        print(f"{query_text:<35} | {top1_doc:<40} | {status}")

    print("\n" + "=" * 80)
    print("SOURCE TYPE FILTER TEST (source_type_filter='cheat_sheets')")
    print("=" * 80)

    filtered_results = retrieve("How to test for reflected XSS?", top_k=5, source_type_filter="cheat_sheets")
    sources = [r.get("metadata", {}).get("source_type") for r in filtered_results]
    print(f"Filter query returned {len(filtered_results)} results with source_types: {set(sources)}")

    testing_guide_count = sum(1 for s in sources if s == "testing_guide")
    if testing_guide_count == 0:
        print("FILTER TEST PASSED: Zero 'testing_guide' results returned when filtering by 'cheat_sheets'.")
    else:
        print(f"FILTER TEST FAILED: Found {testing_guide_count} 'testing_guide' results!")


if __name__ == "__main__":
    main()
