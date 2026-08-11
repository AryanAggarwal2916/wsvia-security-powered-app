"""
CLI tool for testing RAG Q&A end-to-end.
"""

import argparse
from pathlib import Path
import sys

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from retrieval.retriever import retrieve
from generation.generator import generate_answer


def main():
    parser = argparse.ArgumentParser(description="WSVIA CLI Security Assistant Query Tool")
    parser.add_argument(
        "query",
        nargs="?",
        default="How do I prevent SQL injection?",
        help="Security question to ask (default: 'How do I prevent SQL injection?')",
    )
    parser.add_argument(
        "--source-filter",
        default=None,
        help="Optional source type filter (e.g. owasp_top10, cheat_sheets, testing_guide)",
    )
    parser.add_argument("--top-k", type=int, default=5, help="Top K chunks to retrieve (default: 5)")
    args = parser.parse_args()

    query_text = args.query
    print(f"\n[QUERY]: {query_text}")
    print(f"[FILTER]: {args.source_filter or 'All'}")

    print("\nRetrieving chunks...")
    chunks = retrieve(query_text, top_k=args.top_k, source_type_filter=args.source_filter)
    print(f"Retrieved {len(chunks)} chunks from vector store.")

    print("\nGenerating answer via Groq LLM...")
    response = generate_answer(query_text, chunks)

    print("\n" + "=" * 80)
    print("WSVIA SECURITY ASSISTANT RESPONSE")
    print("=" * 80)

    print(f"\n[SEVERITY LABEL]: {response.get('severity')}")
    print("\n[ANSWER TEXT]:")
    print(response.get("answer"))

    print("\n" + "=" * 80)
    print("[CITED SOURCES]:")
    print("=" * 80)
    sources = response.get("sources", [])
    if sources:
        for idx, src in enumerate(sources, start=1):
            doc_name = src.get("document_name", "")
            source_type = src.get("source_type", "")
            path = src.get("source_path", "")
            sev = src.get("severity", "")
            owasp = src.get("owasp_id")
            wstg = src.get("wstg_id")

            id_str = f" | OWASP: {owasp}" if owasp else ""
            id_str += f" | WSTG: {wstg}" if wstg else ""

            print(f"  {idx}. [{source_type}] {doc_name} (Severity: {sev}){id_str}")
            print(f"     Path: {path}")
    else:
        print("  None")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
