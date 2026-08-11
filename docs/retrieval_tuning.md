# WSVIA — Retrieval Tuning Report (Stage 7)

**Date:** 2026-07-31  
**Corpus:** owasp_top10, cheat_sheets, testing_guide  
**Embedding model:** all-MiniLM-L6-v2  
**Evaluation:** 5 queries · hit = expected doc name appears in any top-k result

> **⚠️ Metric caveat — read before trusting the "5/5" numbers below.**
> "Hit rate" here means the expected document appeared *somewhere* in the top-k results, not that it was ranked first. This masks a real ranking issue: the "How to test for reflected XSS?" query consistently returns `01-Testing_for_DOM-based_Cross_Site_Scripting.md` as its **top-1** result across all three configs, when the actually-expected document is `01-Testing_for_Reflected_Cross_Site_Scripting.md`. The correct doc is present in the top-5, so it still counts as a "hit" — but a user reading only the top result would get the wrong page. This persisted across all three tested configs (evidence it's not a chunk_size/top_k tuning problem) and likely needs query expansion or a re-ranking step to fix. Treat "5/5" as "correct doc retrievable," not "correct doc ranked first."

---

## Config 1 — Baseline (chunk_size=256, top_k=5)

- **Chunk size:** 256 tokens
- **top_k:** 5
- **Chunks in index:** 2,389
- **Hit rate:** 5/5

| Query | Top-1 Document | Distance | In top-k? | Note |
|---|---|---|---|---|
| How do I prevent SQL injection? | `SQL_Injection_Prevention_Cheat_Sheet` | 0.5581 | YES | SQL injection cheat sheet / OWASP A05 |
| What is broken access control? | `A01_2025-Broken_Access_Control` | 0.2864 | YES | OWASP A01 — should be clear top-1 |
| How to test for reflected XSS? | `01-Testing_for_DOM-based_Cross_Site_Scripting` | 0.5994 | YES | ⚠️ Wrong doc at top-1 — see metric caveat above. Correct doc (`01-Testing_for_Reflected_Cross_Site_Scripting`) is in top-5 but not ranked first |
| CSRF prevention best practices | `Cross-Site_Request_Forgery_Prevention_Cheat_Sheet` | 0.5864 | YES | Cheat sheet — very targeted query |
| Session management security | `Session_Management_Cheat_Sheet` | 0.5035 | YES | Cheat sheet — broad topic; top-k depth helps |


## Config 2 — Larger chunks (chunk_size=512, top_k=5)

- **Chunk size:** 512 tokens
- **top_k:** 5
- **Chunks in index:** 1,861
- **Hit rate:** 5/5

| Query | Top-1 Document | Distance | In top-k? | Note |
|---|---|---|---|---|
| How do I prevent SQL injection? | `SQL_Injection_Prevention_Cheat_Sheet` | 0.5581 | YES | SQL injection cheat sheet / OWASP A05 |
| What is broken access control? | `A01_2025-Broken_Access_Control` | 0.6084 | YES | OWASP A01 — should be clear top-1 |
| How to test for reflected XSS? | `01-Testing_for_DOM-based_Cross_Site_Scripting` | 0.5994 | YES | ⚠️ Same ranking issue as Config 1 — larger chunks did not fix it |
| CSRF prevention best practices | `Cross-Site_Request_Forgery_Prevention_Cheat_Sheet` | 0.5864 | YES | Cheat sheet — very targeted query |
| Session management security | `Session_Management_Cheat_Sheet` | 0.5035 | YES | Cheat sheet — broad topic; top-k depth helps |


## Config 3 — Wider recall (chunk_size=256, top_k=8)

- **Chunk size:** 256 tokens
- **top_k:** 8
- **Chunks in index:** 2,389
- **Hit rate:** 5/5

| Query | Top-1 Document | Distance | In top-k? | Note |
|---|---|---|---|---|
| How do I prevent SQL injection? | `SQL_Injection_Prevention_Cheat_Sheet` | 0.5581 | YES | SQL injection cheat sheet / OWASP A05 |
| What is broken access control? | `A01_2025-Broken_Access_Control` | 0.2864 | YES | OWASP A01 — should be clear top-1 |
| How to test for reflected XSS? | `01-Testing_for_DOM-based_Cross_Site_Scripting` | 0.5994 | YES | ⚠️ Same ranking issue — wider top-k didn't fix top-1 ranking either |
| CSRF prevention best practices | `Cross-Site_Request_Forgery_Prevention_Cheat_Sheet` | 0.5864 | YES | Cheat sheet — very targeted query |
| Session management security | `Session_Management_Cheat_Sheet` | 0.5035 | YES | Cheat sheet — broad topic; top-k depth helps |


---

## Summary & Recommendation

| Config | chunk_size | top_k | Index size | Hit rate |
|---|---|---|---|---|
| Config 1 — Baseline | 256 | 5 | 2,389 | 5/5 |
| Config 2 — Larger chunks | 512 | 5 | 1,861 | 5/5 |
| Config 3 — Wider recall | 256 | 8 | 2,389 | 5/5 |

### Winner: **Config 1 (baseline: chunk_size=256, top_k=5)** — retained as-is.

Baseline achieves the same or better hit rate as the alternatives. chunk_size=256 aligns tightly with all-MiniLM-L6-v2's 256-token sequence window; doubling to 512 risks blending semantics from multiple sub-topics into one embedding. top_k=5 keeps the LLM context to ~1 280 words — enough signal without padding. **No config.py change needed; index already correct.**

> Index state after this run: chunk_size=256 (baseline restored). `config.py` updated to reflect the recommended values.

### Known limitation carried forward

The reflected-XSS top-1 ranking issue described in the caveat above is **not resolved** by this tuning pass and is not expected to be fixable by chunk_size/top_k adjustments alone — it showed up identically across all three configs. Future work: query expansion (e.g. expanding "reflected XSS" query terms) or a re-ranking step after initial retrieval. Documented here rather than left implicit in the "5/5" headline numbers, and also noted in the project retrospective.