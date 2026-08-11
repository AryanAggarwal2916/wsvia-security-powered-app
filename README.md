# WSVIA — Web Security & Vulnerability Intelligence Assistant

A RAG (Retrieval-Augmented Generation) chatbot for team security knowledge —
ingests OWASP guidance, internal audit reports, CVE data, and past fix notes,
then answers dev questions with cited, severity-aware responses. Includes a
stretch-goal code snippet analyser that maps findings to OWASP Top 10.

## Status
Planning complete, repo scaffolded, implementation not yet started.
See `PROGRESS_LOG.md` (kept outside this repo / in chat) for full decision history.

## Architecture (4 layers)

```
Ingestion   -> ingestion/    load MD/PDF/JSON, tag with source type + severity hints
Indexing    -> indexing/     embed chunks (sentence-transformers), store in ChromaDB
Retrieval   -> retrieval/    query + optional source filter -> top-k chunks
Generation  -> generation/   prompt (context + severity + history) -> Groq LLM -> cited answer
```

Streamlit UI (`ui/`) sits on Retrieval + Generation only — it never touches
Ingestion or Indexing directly. Those run as an offline pipeline that
populates ChromaDB ahead of time.

## Tech stack

| Component | Choice |
|---|---|
| Embeddings | sentence-transformers (`all-MiniLM-L6-v2`) |
| Vector store | ChromaDB (persistent, metadata-filterable) |
| LLM | Groq (free tier, cloud) |
| PDF parsing | PyMuPDF |
| UI | Streamlit |

**Why Groq over Ollama:** avoids repeating past local-processing pain
(OOM/perf issues on Windows with heavy local processes). Groq's LPU
inference is fast and its free tier is sufficient for the demo. Ollama is
noted as an offline fallback, worth mentioning in the retrospective.

## Corpus priority

1. **Critical:** OWASP Top 10
2. **High:** OWASP Testing Guide, Cheat Sheet Series, internal audit reports
   (requested from Rajat Sharma), secure coding guide
3. **Medium:** CVE summaries (NVD/MITRE JSON), past vuln fix notes (git history)

Drop source files into the matching folder under `data/corpus/<source_type>/`.

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # then fill in GROQ_API_KEY
```

## Repo layout

```
wsvia/
├── ingestion/       # Layer 1 — loaders.py, chunking.py
├── indexing/        # Layer 2 — embeddings.py, vector_store.py
├── retrieval/        # Layer 3 — retriever.py
├── generation/       # Layer 4 — prompts.py, llm_client.py, generator.py
├── ui/               # Streamlit app — app.py, code_analyser.py (stretch)
├── data/corpus/      # Source documents by type (gitignored for large PDFs)
├── tests/
├── config.py         # Central paths/model/config constants
└── requirements.txt
```

## Roadmap (3 phases)

- **Phase 1 — Foundation:** ingestion, indexing, retrieval working end-to-end
  via terminal query (no UI yet).
- **Phase 2 — Quality + UI:** Streamlit UI, prompt refinement, retrieval tuning.
- **Phase 3 — Stretch + polish:** code snippet analyser, README, retrospective.

## Not yet done
- [ ] Download OWASP Top 10 + 3 Cheat Sheets into `data/corpus/`
- [ ] Implement document loaders (MD + PDF)
- [ ] Implement chunking strategy
- [ ] Implement embedding + ChromaDB pipeline
- [ ] Implement retrieval function
- [ ] First terminal end-to-end query
- [ ] Get internal audit reports + secure coding guide from Rajat Sharma
- [ ] Streamlit UI
- [ ] Code snippet analyser (stretch)
- [ ] Retrospective
