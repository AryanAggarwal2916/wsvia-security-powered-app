"""
A/B test: old prompts.py vs new (knowledge-grounded) prompts.py.
Same query -> same retrieved context -> two Groq calls (old prompt, new prompt) -> diff.

SETUP (2 things to check before running):
1. Place this file in your project root: C:\\Users\\Windows\\Desktop\\wsvia\\wsvia
2. Confirm the two adapter calls below (RETRIEVE_FN / GENERATE_FN) match your real
   retriever/generator function signatures. Adjust if names differ.
"""

import os
import sys
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# --- adapters: wire these to your real project functions ---
from retrieval.retriever import retrieve as RETRIEVE_FN          # retrieve(query, top_k=5) -> list of chunks
from generation import prompts as new_prompts
from generation import prompts_old as old_prompts

GROQ_MODEL = "llama-3.1-8b-instant"
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))


def format_context(chunks) -> str:
    """Matches real chunk shape: {'text': ..., 'metadata': {'document_name': ..., ...}, ...}"""
    parts = []
    for c in chunks:
        text = c.get("text", "")
        source = c.get("metadata", {}).get("document_name", "unknown")
        parts.append(f"[{source}]\n{text}")
    return "\n\n".join(parts)


def call_groq(system: str, user: str) -> str:
    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.2,
        max_tokens=800,
    )
    return resp.choices[0].message.content


# --- test cases: your 15-query set, or a subset likely to flip behavior ---
# Focus first on queries where retrieval is WEAK or PARTIAL — that's where
# old vs new should diverge (forced-guess vs "not determinable").
TEST_QUERIES = [
    "What's the severity of a stored XSS vulnerability in our login form?",
    "Give me an example of Broken Access Control with CVSS 10.0",
    "Explain Log4Shell CVE",
    "What's the severity of a buffer overflow in our payment gateway?",
]

CHAT_HISTORY = "None"

# --- code analyser test cases ---
# Snippet A: clean, unambiguous OWASP match (SQL injection via string concat).
# Snippet B: weak/ambiguous match — unusual pattern less likely to cleanly map
# to a single OWASP category in your corpus, tests the "no forced mapping" rule.
TEST_CODE_SNIPPETS = [
    (
        "SQL Injection (clean match)",
        'query = "SELECT * FROM users WHERE username = \'" + user_input + "\'"\n'
        'cursor.execute(query)',
    ),
    (
        "Ambiguous / weak match",
        "import pickle\n"
        "def load_session(data):\n"
        "    return pickle.loads(data)  # deserializes raw bytes from an incoming request",
    ),
]


def run_qa():
    for i, question in enumerate(TEST_QUERIES, 1):
        chunks = RETRIEVE_FN(question, top_k=5)
        context = format_context(chunks)

        old = old_prompts.build_qa_prompt_old(context, CHAT_HISTORY, question)
        new = new_prompts.build_qa_prompt(context, CHAT_HISTORY, question)

        old_answer = call_groq(old["system"], old["user"])
        new_answer = call_groq(new["system"], new["user"])

        print("=" * 80)
        print(f"QA QUERY {i}: {question}")
        print("-" * 80)
        print(f"[RETRIEVED CONTEXT PREVIEW]\n{context[:300]}...\n")
        print("[OLD PROMPT ANSWER]")
        print(old_answer)
        print("\n[NEW PROMPT ANSWER]")
        print(new_answer)
        print()


def run_code_analyser():
    for i, (label, snippet) in enumerate(TEST_CODE_SNIPPETS, 1):
        # Using the snippet itself as retrieval query — swap this for your real
        # snippet-aware query builder from ui/code_analyser.py if it differs.
        chunks = RETRIEVE_FN(snippet, top_k=5)
        context = format_context(chunks)

        old = old_prompts.build_code_analysis_prompt_old(snippet, context)
        new = new_prompts.build_code_analysis_prompt(snippet, context)

        old_answer = call_groq(old["system"], old["user"])
        new_answer = call_groq(new["system"], new["user"])

        print("=" * 80)
        print(f"CODE SNIPPET {i}: {label}")
        print("-" * 80)
        print(f"[RETRIEVED CONTEXT PREVIEW]\n{context[:300]}...\n")
        print("[OLD PROMPT ANSWER]")
        print(old_answer)
        print("\n[NEW PROMPT ANSWER]")
        print(new_answer)
        print()


if __name__ == "__main__":
    run_qa()
    run_code_analyser()