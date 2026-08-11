"""
Offline indexing script for WSVIA.

Loads corpus, generates chunks and embeddings, and populates persistent ChromaDB vector store.
Supports --reset flag to delete and rebuild collection from scratch.
"""

import argparse
from pathlib import Path
import sys
import time

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ingestion.loaders import load_source_directory
from ingestion.chunking import chunk_all
from indexing.embeddings import embed_texts
from indexing.vector_store import add_chunks, reset_collection, get_collection


def main():
    parser = argparse.ArgumentParser(description="Build persistent ChromaDB index for WSVIA corpus.")
    parser.add_argument("--reset", action="store_true", help="Delete and rebuild the collection from scratch.")
    args = parser.parse_args()

    start_time = time.time()

    if args.reset:
        print("Reset flag provided. Resetting ChromaDB collection...")
        collection = reset_collection()
    else:
        collection = get_collection()

    print("Step 1: Loading raw documents from data/corpus...")
    docs = load_source_directory("data/corpus")
    print(f"Loaded {len(docs)} raw documents.")

    print("Step 2: Chunking documents (heading-aware)...")
    chunks = chunk_all(docs)
    print(f"Generated {len(chunks)} text chunks.")

    if not chunks:
        print("No chunks to index. Exiting.")
        return

    print("Step 3: Generating embeddings (all-MiniLM-L6-v2)...")
    texts = [c["text"] for c in chunks]
    embeddings = embed_texts(texts)
    print(f"Generated {len(embeddings)} embeddings.")

    print("Step 4: Inserting chunks & metadata into ChromaDB vector store...")
    add_chunks(chunks, embeddings, batch_size=100)

    count = collection.count()
    elapsed = time.time() - start_time

    print("=" * 70)
    print(f"INDEXING COMPLETE in {elapsed:.2f} seconds.")
    print(f"Total chunks indexed in ChromaDB collection: {count}")
    print("=" * 70)


if __name__ == "__main__":
    main()
