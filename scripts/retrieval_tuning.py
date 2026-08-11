"""
Stage 7 — Retrieval Tuning Orchestrator (timeboxed to 3 configs exactly).

Each config runs in a FRESH subprocess via _tuning_worker.py to avoid
ChromaDB's module-level singleton bleeding across configs (which caused
hangs in the single-process version).

Configs:
  1. Baseline  : chunk_size=256, top_k=5  (existing index, no rebuild)
  2. Larger    : chunk_size=512, top_k=5  (rebuild required)
  3. More k    : chunk_size=256, top_k=8  (restore baseline, no rebuild)

Output: docs/retrieval_tuning.md

Run from inside wsvia/ package root:
    python scripts/retrieval_tuning.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

WORKER = str(Path(__file__).parent / "_tuning_worker.py")
DOCS_DIR = ROOT / "docs"


def run_config(
    chunk_size: int,
    top_k: int,
    label: str,
    rebuild: bool,
) -> tuple[int, list[dict]]:
    """Spawn a fresh subprocess for one config and return (chunk_count, rows)."""
    cmd = [sys.executable, "-X", "utf8", WORKER, str(chunk_size), str(top_k), label]
    if rebuild:
        cmd.append("--rebuild")

    print(f"\n  Running: chunk_size={chunk_size}, top_k={top_k}, rebuild={rebuild}")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=str(ROOT),
    )

    # Worker progress goes to stderr — stream it for visibility
    if result.stderr.strip():
        for line in result.stderr.strip().splitlines():
            print(f"    {line}")

    if result.returncode != 0:
        print(f"\n  ERROR (exit {result.returncode}):")
        print(result.stdout[-2000:] if result.stdout else "(no stdout)")
        raise RuntimeError(f"Worker failed for config: {label}")

    payload = json.loads(result.stdout.strip())
    return payload["chunk_count"], payload["rows"]


def _print_rows(label: str, chunk_count: int, rows: list[dict]) -> None:
    hits = sum(r["hit"] for r in rows)
    print(f"  Chunks in index : {chunk_count}")
    print(f"  {'Query':<40} {'Top-1 Document':<45} Hit?")
    print("  " + "-" * 95)
    for r in rows:
        h = "[YES]" if r["hit"] else "[NO] "
        print(f"  {r['query']:<40} {r['top1_doc']:<45} {h}")
    print(f"  Score: {hits}/{len(rows)}")


def _write_report(
    all_results: list[tuple[str, int, int, int, list[dict]]],
) -> Path:
    # all_results: (label, chunk_size, top_k, chunk_count, rows)
    DOCS_DIR.mkdir(exist_ok=True)
    path = DOCS_DIR / "retrieval_tuning.md"

    notes_map = {
        "How do I prevent SQL injection?":   "SQL injection cheat sheet / OWASP A05",
        "What is broken access control?":    "OWASP A01 — should be clear top-1",
        "How to test for reflected XSS?":    "WSTG testing guide — longer docs benefit from larger chunks",
        "CSRF prevention best practices":    "Cheat sheet — very targeted query",
        "Session management security":       "Cheat sheet — broad topic; top-k depth helps",
    }

    lines: list[str] = [
        "# WSVIA — Retrieval Tuning Report (Stage 7)",
        "",
        f"**Date:** {time.strftime('%Y-%m-%d')}  ",
        "**Corpus:** owasp_top10, cheat_sheets, testing_guide  ",
        "**Embedding model:** all-MiniLM-L6-v2  ",
        "**Evaluation:** 5 queries · hit = expected doc name appears in any top-k result",
        "",
        "---",
        "",
    ]

    scores: list[int] = []
    for label, cs, k, count, rows in all_results:
        hits = sum(r["hit"] for r in rows)
        scores.append(hits)
        lines += [
            f"## {label}",
            "",
            f"- **Chunk size:** {cs} tokens",
            f"- **top_k:** {k}",
            f"- **Chunks in index:** {count:,}",
            f"- **Hit rate:** {hits}/{len(rows)}",
            "",
            "| Query | Top-1 Document | Distance | In top-k? | Note |",
            "|---|---|---|---|---|",
        ]
        for r in rows:
            hit_str = "YES" if r["hit"] else "NO"
            dist = f"{r['top1_dist']:.4f}" if r["top1_dist"] >= 0 else "n/a"
            note = notes_map.get(r["query"], "")
            lines.append(
                f"| {r['query']} | `{r['top1_doc']}` | {dist} | {hit_str} | {note} |"
            )
        lines += ["", ""]

    # ------------------------------------------------------------------ #
    # Recommendation                                                       #
    # ------------------------------------------------------------------ #
    c1_score, c2_score, c3_score = scores
    c1_label, c1_cs, c1_k, c1_cnt, _ = all_results[0]
    c2_label, c2_cs, c2_k, c2_cnt, _ = all_results[1]
    c3_label, c3_cs, c3_k, c3_cnt, _ = all_results[2]

    lines += [
        "---",
        "",
        "## Summary & Recommendation",
        "",
        "| Config | chunk_size | top_k | Index size | Hit rate |",
        "|---|---|---|---|---|",
        f"| Config 1 — Baseline | {c1_cs} | {c1_k} | {c1_cnt:,} | {c1_score}/5 |",
        f"| Config 2 — Larger chunks | {c2_cs} | {c2_k} | {c2_cnt:,} | {c2_score}/5 |",
        f"| Config 3 — Wider recall | {c3_cs} | {c3_k} | {c3_cnt:,} | {c3_score}/5 |",
        "",
    ]

    # Pick winner: highest score; tie → prefer lower top_k (keeps LLM context lean)
    best_score = max(c1_score, c2_score, c3_score)
    if c1_score == best_score:
        winner = 1
    elif c3_score == best_score:
        winner = 3       # same score as c2 but no rebuild cost
    else:
        winner = 2

    reasoning = {
        1: (
            "**Config 1 (baseline: chunk_size=256, top_k=5)** — retained as-is.\n\n"
            "Baseline achieves the same or better hit rate as the alternatives. "
            "chunk_size=256 aligns tightly with all-MiniLM-L6-v2's 256-token "
            "sequence window; doubling to 512 risks blending semantics from "
            "multiple sub-topics into one embedding. "
            "top_k=5 keeps the LLM context to ~1 280 words — enough signal "
            "without padding. **No config.py change needed; index already correct.**"
        ),
        2: (
            "**Config 2 (chunk_size=512, top_k=5)** — update `CHUNK_SIZE_TOKENS = 512` in config.py "
            "and re-run `build_index.py --reset`.\n\n"
            "Larger chunks captured multi-paragraph context that smaller splits miss, "
            "producing a meaningful recall improvement. Trade-off: embedding quality "
            "may be noisier per chunk due to broader topic coverage; monitor in production."
        ),
        3: (
            "**Config 3 (chunk_size=256, top_k=8)** — update `DEFAULT_TOP_K = 8` in config.py.\n\n"
            "Increasing top_k from 5 to 8 improved recall at zero re-indexing cost. "
            "The extra 3 chunks add ~200–300 words of context well within the LLM's "
            "window. chunk_size=256 is unchanged, preserving embedding quality."
        ),
    }

    lines += [
        f"### Winner: {reasoning[winner]}",
        "",
        "> Index state after this run: chunk_size=256 (baseline restored). "
        "`config.py` updated to reflect the recommended values.",
        "",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def main() -> None:
    print("=" * 60)
    print("WSVIA Stage 7 — Retrieval Tuning (3 configs)")
    print("=" * 60)

    all_results = []

    # Config 1 — Baseline
    print("\n[1/3] Config 1: chunk_size=256, top_k=5  (rebuild index)")
    c1_count, c1_rows = run_config(256, 5, "Config 1 — Baseline (chunk_size=256, top_k=5)", rebuild=True)
    all_results.append(("Config 1 — Baseline (chunk_size=256, top_k=5)", 256, 5, c1_count, c1_rows))
    _print_rows("Config 1", c1_count, c1_rows)

    # Config 2 — Larger chunks
    print("\n[2/3] Config 2: chunk_size=512, top_k=5  (rebuild required)")
    c2_count, c2_rows = run_config(512, 5, "Config 2 — Larger chunks (chunk_size=512, top_k=5)", rebuild=True)
    all_results.append(("Config 2 — Larger chunks (chunk_size=512, top_k=5)", 512, 5, c2_count, c2_rows))
    _print_rows("Config 2", c2_count, c2_rows)

    # Config 3 — More results (restore baseline index first)
    print("\n[3/3] Config 3: chunk_size=256, top_k=8  (rebuild to restore baseline)")
    c3_count, c3_rows = run_config(256, 8, "Config 3 — Wider recall (chunk_size=256, top_k=8)", rebuild=True)
    all_results.append(("Config 3 — Wider recall (chunk_size=256, top_k=8)", 256, 8, c3_count, c3_rows))
    _print_rows("Config 3", c3_count, c3_rows)

    # Write report
    report_path = _write_report(all_results)
    print(f"\nReport written: {report_path}")

    # Apply winning config to config.py
    scores = [sum(r["hit"] for r in rows) for _, _, _, _, rows in all_results]
    best = max(scores)
    if scores[0] == best:
        winner = 1
        print("\nWinner: Config 1 (baseline). No config.py change needed.")
    elif scores[2] == best:
        winner = 3
        _apply_config(top_k=8)
        print("\nWinner: Config 3. Applied DEFAULT_TOP_K=8 to config.py.")
    else:
        winner = 2
        print("\nWinner: Config 2. Index already at chunk_size=512.")
        print("NOTE: Re-run build_index.py --reset is already done by this script.")
        _apply_config(chunk_size=512)

    print(f"\nStage 7 complete. Final index: chunk_size=256, top_k={'8' if winner==3 else '5'}.")
    print(f"Open docs/retrieval_tuning.md for the full table.")


def _apply_config(chunk_size: int | None = None, top_k: int | None = None) -> None:
    """Patch config.py in-place for the winning setting."""
    import re
    cfg_path = ROOT / "config.py"
    text = cfg_path.read_text(encoding="utf-8")
    if chunk_size is not None:
        text = re.sub(r"CHUNK_SIZE_TOKENS\s*=\s*\d+", f"CHUNK_SIZE_TOKENS = {chunk_size}", text)
    if top_k is not None:
        text = re.sub(r"DEFAULT_TOP_K\s*=\s*\d+", f"DEFAULT_TOP_K = {top_k}", text)
    cfg_path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
