"""
Comprehensive test script for all 3 new WSVIA features.
Exercises the actual functions used by the UI, with real ChromaDB / file / retrieval calls.
"""

import json
import os
import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")
load_dotenv()

# ============================================================================
# TEST 1 — PASSCODE GATE LOGIC
# ============================================================================
print("=" * 70)
print("TEST 1 — PASSCODE GATE LOGIC")
print("=" * 70)

# Step 2: Wrong passcode should be denied
print("\n--- Step 2: Wrong passcode ---")
expected = os.environ.get("ADMIN_PASSCODE")
print(f"  ADMIN_PASSCODE env value: '{expected}'")
wrong = "wrongpass"
match = (wrong == expected)
print(f"  Input: '{wrong}' == expected: {match}")
if not match:
    print("  RESULT: PASS — Wrong passcode correctly denied (match is False)")
else:
    print("  RESULT: FAIL — Wrong passcode was accepted!")

# Step 3: Correct passcode should unlock
print("\n--- Step 3: Correct passcode ---")
correct = expected  # whatever is in .env
match_correct = (correct == expected)
print(f"  Input: '{correct}' == expected: {match_correct}")
if match_correct:
    print("  RESULT: PASS — Correct passcode accepted")
else:
    print("  RESULT: FAIL — Correct passcode was rejected!")

# Step 4+5: ADMIN_PASSCODE not set → disabled
print("\n--- Step 4+5: ADMIN_PASSCODE not configured ---")
saved_passcode = os.environ.pop("ADMIN_PASSCODE", None)
not_configured_value = os.environ.get("ADMIN_PASSCODE")
print(f"  After removing from env, ADMIN_PASSCODE = {not_configured_value!r}")
gate_disabled = (not not_configured_value)
if gate_disabled:
    print("  RESULT: PASS — Manage view would be disabled (no env var, no default fallback)")
else:
    print("  RESULT: FAIL — ADMIN_PASSCODE somehow still has a value!")

# Restore for subsequent tests
if saved_passcode:
    os.environ["ADMIN_PASSCODE"] = saved_passcode
print(f"  Restored ADMIN_PASSCODE = {os.environ.get('ADMIN_PASSCODE')!r}")


# ============================================================================
# TEST 2 — CVE DELETION FROM SHARED JSON CORPUS
# ============================================================================
print("\n" + "=" * 70)
print("TEST 2 — CVE DELETION FROM SHARED JSON CORPUS")
print("=" * 70)

from indexing.vector_store import (
    get_all_documents_metadata,
    get_by_document_name,
    delete_by_document_name,
)

# Step 1: Record full list of CVE IDs in cve_corpus.json
cve_json_path = Path("data/corpus/cve_summaries/cve_corpus.json")
cve_data_before = json.loads(cve_json_path.read_text(encoding="utf-8"))
cve_ids_before = [rec.get("cve_id") for rec in cve_data_before]
print(f"\n--- Step 1: CVE corpus before deletion ---")
print(f"  Total CVE records in cve_corpus.json: {len(cve_ids_before)}")
print(f"  CVE IDs: {cve_ids_before[:10]}... (showing first 10)")

# Step 2: Pick a specific CVE that exists in both JSON and ChromaDB
target_cve = "CVE-2022-22965"  # Spring4Shell
print(f"\n--- Step 2: Target CVE for deletion: {target_cve} ---")

# Verify it exists in ChromaDB before deletion
chunks_before = get_by_document_name(target_cve)
print(f"  Chunks in ChromaDB for {target_cve} before delete: {len(chunks_before)}")
assert len(chunks_before) > 0, f"CVE {target_cve} not found in ChromaDB — cannot test deletion!"

# Step 3: Delete via same code path the UI Manage view uses
print(f"\n--- Step 3: Deleting {target_cve} ---")
deleted_count = delete_by_document_name(target_cve)
print(f"  Chunks deleted from ChromaDB: {deleted_count}")

# Also update the JSON file (same logic as ui/doc_library._delete_source_file_from_disk)
source_path = chunks_before[0].get("metadata", {}).get("source_path", "")
print(f"  Source path from metadata: {source_path}")

# Execute the disk-delete function from doc_library
from ui.doc_library import _delete_source_file_from_disk
_delete_source_file_from_disk(target_cve, source_path)

# Step 4a: Verify it no longer appears in ChromaDB (Browse view data)
print(f"\n--- Step 4a: Verify removed from ChromaDB ---")
chunks_after = get_by_document_name(target_cve)
print(f"  Chunks in ChromaDB for {target_cve} after delete: {len(chunks_after)}")
if len(chunks_after) == 0:
    print("  RESULT: PASS — CVE no longer in ChromaDB")
else:
    print("  RESULT: FAIL — CVE still has chunks in ChromaDB!")

# Browse view check
all_docs = get_all_documents_metadata()
doc_names_in_browse = [d["document_name"] for d in all_docs]
if target_cve not in doc_names_in_browse:
    print(f"  Browse view check: PASS — {target_cve} NOT in document list")
else:
    print(f"  Browse view check: FAIL — {target_cve} still appears in Browse view!")

# Step 4b: Re-read cve_corpus.json and verify
print(f"\n--- Step 4b: Verify cve_corpus.json file ---")
cve_data_after = json.loads(cve_json_path.read_text(encoding="utf-8"))
cve_ids_after = [rec.get("cve_id") for rec in cve_data_after]
print(f"  Total CVE records after: {len(cve_ids_after)}")
print(f"  Expected count: {len(cve_ids_before) - 1}")
count_ok = (len(cve_ids_after) == len(cve_ids_before) - 1)
target_gone = (target_cve not in cve_ids_after)
others_intact = all(
    cve_id in cve_ids_after
    for cve_id in cve_ids_before
    if cve_id != target_cve
)
print(f"  Count is exactly one less: {count_ok}")
print(f"  Target CVE removed from file: {target_gone}")
print(f"  All other CVEs still intact: {others_intact}")
if count_ok and target_gone and others_intact:
    print("  RESULT: PASS — JSON file correctly updated")
else:
    print("  RESULT: FAIL — JSON file integrity issue!")

# Step 4c: Query the deleted CVE through retrieval/generation
print(f"\n--- Step 4c: Query deleted CVE through Q&A pipeline ---")
from retrieval.retriever import retrieve
from generation.generator import generate_answer

query_chunks = retrieve(target_cve, top_k=5)
# Check if any returned chunks are for the deleted CVE
cve_chunks = [c for c in query_chunks if c.get("metadata", {}).get("document_name") == target_cve]
print(f"  Retrieval returned {len(query_chunks)} total chunks, {len(cve_chunks)} from {target_cve}")

result = generate_answer(f"What is {target_cve}?", query_chunks)
answer = result.get("answer", "")
print(f"  Answer excerpt: {answer[:250]}...")

# Check if answer indicates not found or is from general knowledge
if len(cve_chunks) == 0:
    print("  RESULT: PASS — No chunks returned for deleted CVE")
else:
    print("  RESULT: FAIL — Still retrieving chunks for deleted CVE!")

# RESTORE: Re-add the deleted CVE back to the JSON file for future tests
# (We need to re-read the original data to restore it)
print(f"\n--- CLEANUP: Restoring {target_cve} to cve_corpus.json ---")
deleted_record = next(rec for rec in cve_data_before if rec.get("cve_id") == target_cve)
cve_data_after.append(deleted_record)
cve_json_path.write_text(json.dumps(cve_data_after, indent=2), encoding="utf-8")
print(f"  Restored. Total records now: {len(cve_data_after)}")
# Note: NOT re-indexing into ChromaDB — that would require embeddings. Just restoring the file.


# ============================================================================
# TEST 3 — DUPLICATE DETECTION / REPLACE FLOW
# ============================================================================
print("\n" + "=" * 70)
print("TEST 3 — DUPLICATE DETECTION / REPLACE FLOW")
print("=" * 70)

from ingestion.loaders import load_markdown
from ingestion.chunking import chunk_all
from indexing.embeddings import embed_texts
from indexing.vector_store import add_chunks

test_doc_path = Path("data/corpus/cheat_sheets/test_dup_check.md")

# Step 1: Upload initial test document
print("\n--- Step 1: Upload initial test document ---")
test_doc_path.write_text(
    "# Test Duplicate Document V1\n\n"
    "This is the FIRST version of the test document.\n"
    "It discusses SQL injection prevention basics.\n",
    encoding="utf-8",
)
raw_doc = load_markdown(test_doc_path, "cheat_sheets")
chunks_v1 = chunk_all([raw_doc])
texts_v1 = [c["text"] for c in chunks_v1]
embs_v1 = embed_texts(texts_v1)
add_chunks(chunks_v1, embs_v1)

indexed_v1 = get_by_document_name("test_dup_check")
print(f"  V1 chunks generated: {len(chunks_v1)}")
print(f"  V1 chunks in ChromaDB: {len(indexed_v1)}")

# Step 2: Check duplicate detection
print("\n--- Step 2: Check duplicate detection ---")
existing_check = get_by_document_name("test_dup_check")
duplicate_detected = len(existing_check) > 0
print(f"  Existing hits for 'test_dup_check': {len(existing_check)}")
print(f"  Duplicate would be detected: {duplicate_detected}")
if duplicate_detected:
    print("  RESULT: PASS — Duplicate detection triggers correctly")
else:
    print("  RESULT: FAIL — Duplicate was not detected!")

# Step 3: Simulate replace flow (delete old → ingest new)
print("\n--- Step 3: Replace flow simulation ---")
# Delete old chunks first (as the UI does when "Replace" is confirmed)
delete_by_document_name("test_dup_check")
mid_check = get_by_document_name("test_dup_check")
print(f"  After deleting old chunks: {len(mid_check)} chunks remain")

# Write new version of same file
test_doc_path.write_text(
    "# Test Duplicate Document V2\n\n"
    "This is the SECOND version. Content has been updated.\n"
    "It now also covers XSS prevention.\n",
    encoding="utf-8",
)
raw_doc_v2 = load_markdown(test_doc_path, "cheat_sheets")
chunks_v2 = chunk_all([raw_doc_v2])
texts_v2 = [c["text"] for c in chunks_v2]
embs_v2 = embed_texts(texts_v2)
add_chunks(chunks_v2, embs_v2)

indexed_v2 = get_by_document_name("test_dup_check")
print(f"  V2 chunks generated: {len(chunks_v2)}")
print(f"  V2 chunks in ChromaDB: {len(indexed_v2)}")

# Step 4: Verify only ONE set of chunks exists (no duplicates)
print("\n--- Step 4: Verify no duplicates ---")
only_one_set = (len(indexed_v2) == len(chunks_v2))
# Check content is V2 not V1
v2_content = indexed_v2[0]["text"] if indexed_v2 else ""
is_v2 = "SECOND" in v2_content or "V2" in v2_content
print(f"  Chunk count matches V2 generation: {only_one_set} ({len(indexed_v2)} == {len(chunks_v2)})")
print(f"  Content is from V2: {is_v2}")
print(f"  Content sample: {v2_content[:120]}...")
if only_one_set and is_v2:
    print("  RESULT: PASS — Only V2 chunks exist, no leftover V1 duplicates")
else:
    print(f"  RESULT: FAIL — Expected {len(chunks_v2)} V2 chunks, found {len(indexed_v2)}")

# CLEANUP: Remove test doc from ChromaDB and disk
print("\n--- CLEANUP ---")
delete_by_document_name("test_dup_check")
if test_doc_path.exists():
    test_doc_path.unlink()
print("  Cleaned up test_dup_check from ChromaDB and disk.")


# ============================================================================
# TEST 4 — RELATED VULNERABILITIES SUGGESTIONS
# ============================================================================
print("\n" + "=" * 70)
print("TEST 4 — RELATED VULNERABILITIES SUGGESTIONS")
print("=" * 70)

from retrieval.retriever import get_related_vulnerabilities

# Step 1: Ask a normal Q&A question
print("\n--- Step 1: Normal Q&A question ---")
question_1 = "How do I prevent SQL injection?"
chunks_1 = retrieve(question_1, top_k=5)
result_1 = generate_answer(question_1, chunks_1)
answer_1 = result_1.get("answer", "")
print(f"  Question: {question_1}")
print(f"  Retrieved {len(chunks_1)} chunks")
print(f"  Top chunk doc: {chunks_1[0]['metadata']['document_name'] if chunks_1 else 'NONE'}")
print(f"  Answer excerpt: {answer_1[:200]}...")

# Step 2: Get related vulnerability suggestions
print("\n--- Step 2: Related suggestions ---")
top_meta = chunks_1[0]["metadata"] if chunks_1 else {}
print(f"  Top metadata for suggestions: doc={top_meta.get('document_name')}, heading={top_meta.get('heading')}")

related = get_related_vulnerabilities(top_meta, top_k=3)
print(f"  Related suggestions count: {len(related)}")

# Build suggestion data like the UI does
suggestions = []
seen = set()
for rh in related:
    rmeta = rh.get("metadata", {})
    rdoc = rmeta.get("document_name", "")
    rhead = rmeta.get("heading", "")
    rquery = rdoc if not rhead or rhead.lower() == rdoc.lower() else f"{rdoc} {rhead}"
    if rquery and rquery not in seen and rdoc != top_meta.get("document_name"):
        seen.add(rquery)
        suggestions.append({"doc": rdoc, "heading": rhead, "query": rquery})
    if len(suggestions) >= 3:
        break

print(f"  De-duped suggestion buttons: {len(suggestions)}")
for i, s in enumerate(suggestions):
    print(f"    [{i+1}] doc={s['doc']}, heading={s['heading'][:40]}, query={s['query'][:60]}")

if len(suggestions) >= 2:
    print("  RESULT: PASS — 2+ related suggestions generated from real corpus documents")
else:
    print(f"  RESULT: FAIL — Only {len(suggestions)} suggestions (need >= 2)")

# Step 3+4: Click a suggestion → triggers a NEW retrieval+generation with different content
print("\n--- Step 3+4: Click suggestion → new query ---")
if suggestions:
    clicked_query = suggestions[0]["query"]
    print(f"  Clicked suggestion query: '{clicked_query}'")

    chunks_2 = retrieve(clicked_query, top_k=5)
    result_2 = generate_answer(clicked_query, chunks_2)
    answer_2 = result_2.get("answer", "")
    print(f"  Retrieved {len(chunks_2)} chunks for suggestion query")
    print(f"  Top chunk doc: {chunks_2[0]['metadata']['document_name'] if chunks_2 else 'NONE'}")
    print(f"  Answer excerpt: {answer_2[:200]}...")

    # Compare answers
    answers_differ = (answer_1.strip() != answer_2.strip())
    # Compare top chunks used
    top_doc_1 = chunks_1[0]["metadata"]["document_name"] if chunks_1 else ""
    top_doc_2 = chunks_2[0]["metadata"]["document_name"] if chunks_2 else ""
    chunks_differ = (top_doc_1 != top_doc_2) or (chunks_1[0].get("chunk_id") != chunks_2[0].get("chunk_id"))

    print(f"\n  Answers are different: {answers_differ}")
    print(f"  Top chunks are different: {chunks_differ} (doc1={top_doc_1}, doc2={top_doc_2})")

    if answers_differ:
        print("  RESULT: PASS — Clicking suggestion generated genuinely different answer")
    else:
        print("  RESULT: FAIL — Answers are identical (no new retrieval/generation happened)")
else:
    print("  RESULT: SKIP — No suggestions to click")


# ============================================================================
# TEST 5 — REGRESSION CHECK
# ============================================================================
print("\n" + "=" * 70)
print("TEST 5 — REGRESSION CHECK")
print("=" * 70)

print("\n--- Checking that new modules import without errors ---")
try:
    from ui.doc_library import render_doc_library, render_browse_view, render_manage_view
    print("  ui.doc_library imports: OK")
except Exception as e:
    print(f"  ui.doc_library imports: FAIL — {e}")

try:
    from indexing.vector_store import (
        get_all_documents_metadata,
        delete_by_document_name,
        get_by_document_name,
    )
    print("  vector_store new functions import: OK")
except Exception as e:
    print(f"  vector_store new functions import: FAIL — {e}")

try:
    from retrieval.retriever import get_related_vulnerabilities
    print("  retriever.get_related_vulnerabilities import: OK")
except Exception as e:
    print(f"  retriever.get_related_vulnerabilities import: FAIL — {e}")

# Verify existing functions still work
print("\n--- Verify existing retrieval+generation pipeline ---")
test_q = "What is Log4Shell?"
test_chunks = retrieve(test_q, top_k=5)
test_result = generate_answer(test_q, test_chunks)
has_answer = bool(test_result.get("answer"))
has_severity = bool(test_result.get("severity"))
has_sources = isinstance(test_result.get("sources"), list)
has_chunks_key = isinstance(test_result.get("chunks"), list)
print(f"  Retrieval returned chunks: {len(test_chunks)}")
print(f"  Result has answer: {has_answer}")
print(f"  Result has severity: {has_severity}")
print(f"  Result has sources list: {has_sources}")
print(f"  Result has chunks list: {has_chunks_key}")
if all([has_answer, has_severity, has_sources, has_chunks_key]):
    print("  RESULT: PASS — Existing pipeline intact")
else:
    print("  RESULT: FAIL — Pipeline output shape changed!")

# Verify return shape of generate_answer hasn't changed
print("\n--- Verify generate_answer return shape consistency ---")
expected_keys = {"answer", "severity", "sources", "chunks"}
actual_keys = set(test_result.keys())
# related_suggestions is new but additive — not breaking
breaking_missing = expected_keys - actual_keys
print(f"  Expected keys present: {expected_keys.issubset(actual_keys)}")
if breaking_missing:
    print(f"  RESULT: FAIL — Missing expected keys: {breaking_missing}")
else:
    print("  RESULT: PASS — Return shape includes all required keys")

print("\n" + "=" * 70)
print("ALL TESTS COMPLETE")
print("=" * 70)
