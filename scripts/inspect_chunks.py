"""
Inspect generated chunks and metadata across corpus source types.
"""

from collections import Counter, defaultdict
from pathlib import Path
import sys

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ingestion.loaders import load_source_directory
from ingestion.chunking import chunk_all
from config import SOURCE_TYPES


def main():
    print("Loading documents from data/corpus...")
    docs = load_source_directory("data/corpus")
    print(f"Total raw documents loaded: {len(docs)}")

    print("Chunking documents...")
    chunks = chunk_all(docs)
    print(f"Total chunks generated: {len(chunks)}\n")

    chunks_by_type = defaultdict(list)
    for c in chunks:
        chunks_by_type[c["source_type"]].append(c)

    print("=" * 80)
    print("FIRST 5 CHUNKS PER SOURCE TYPE:")
    print("=" * 80)

    for st in SOURCE_TYPES:
        st_chunks = chunks_by_type[st]
        print(f"\n--- Source Type: {st} (Total chunks: {len(st_chunks)}) ---")
        for idx, chunk in enumerate(st_chunks[:5]):
            print(f"\n[Chunk #{idx + 1}] ID: {chunk['chunk_id']}")
            print(f"Document Name: {chunk['document_name']}")
            print(f"Heading: {chunk.get('heading')}")
            print(f"Severity: {chunk['severity']}")
            print(f"OWASP ID: {chunk['owasp_id']}")
            print(f"WSTG ID: {chunk['wstg_id']}")
            print("Preview:")
            preview = chunk['text'][:200].replace('\n', ' ')
            print(f"  {preview}...")

    print("\n" + "=" * 80)
    print("METADATA NONE-COUNT SUMMARY PER SOURCE TYPE:")
    print("=" * 80)

    for st in SOURCE_TYPES:
        st_chunks = chunks_by_type[st]
        total = len(st_chunks)
        if total == 0:
            print(f"{st}: 0 chunks")
            continue

        owasp_none = sum(1 for c in st_chunks if c["owasp_id"] is None)
        wstg_none = sum(1 for c in st_chunks if c["wstg_id"] is None)

        owasp_pct = (owasp_none / total) * 100
        wstg_pct = (wstg_none / total) * 100

        print(
            f"{st}: {total} chunks | "
            f"owasp_id=None: {owasp_none}/{total} ({owasp_pct:.1f}%) | "
            f"wstg_id=None: {wstg_none}/{total} ({wstg_pct:.1f}%)"
        )


if __name__ == "__main__":
    main()
