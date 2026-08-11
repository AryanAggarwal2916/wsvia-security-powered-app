from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from ingestion.loaders import load_source_directory
from ingestion.chunking import chunk_document
from config import CHUNK_SIZE_TOKENS, CHUNK_OVERLAP_TOKENS

docs = load_source_directory('data/corpus')
tg_docs = [d for d in docs if d['source_type'] == 'testing_guide']

counts = [(d['document_name'], len(chunk_document(d))) for d in tg_docs]
sorted_counts = sorted(counts, key=lambda x: x[1], reverse=True)

print(f"CHUNK_SIZE_TOKENS in config: {CHUNK_SIZE_TOKENS}")
print(f"CHUNK_OVERLAP_TOKENS in config: {CHUNK_OVERLAP_TOKENS}")
print("\nTop 5 files by chunk count in testing_guide:")
for name, c in sorted_counts[:5]:
    print(f"  {name}: {c} chunks")

target_doc = next(d for d in tg_docs if d['document_name'] == '05-Testing_for_SQL_Injection')
chunks = chunk_document(target_doc)

print(f"\nDetailed breakdown for 05-Testing_for_SQL_Injection ({len(chunks)} chunks):")
for idx, c in enumerate(chunks):
    word_cnt = len(c["text"].split())
    char_cnt = len(c["text"])
    print(f"Chunk #{idx+1:02d} | Heading: {c.get('heading'):<55} | Words: {word_cnt:3d} | Chars: {char_cnt:4d}")

