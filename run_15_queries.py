import json
from retrieval.retriever import retrieve
from generation.generator import generate_answer

queries = [
    "What CVE corresponds to Log4Shell and what OWASP category is it?",
    "What is the CVSS score of CVE-2020-1472 (Zerologon)?",
    "What CWE IDs are associated with CVE-2021-44228?",
    "What vulnerability class is CVE-2023-20198?",
    "When was CVE-2020-0601 published?",
    "What's an example of a Broken Access Control vulnerability with CVSS 10.0?",
    "Compare CVE-2021-44228 and CVE-2022-22947 — what do they have in common?",
    "Which CVEs in the corpus fall under A05:2025 Injection with CVSS 9.8 or higher?",
    "What OWASP category does ProxyLogon (CVE-2021-27065) fall under, and why?",
    "Explain why CVE-2020-1472 is dangerous despite a 5.5 CVSS score.",
    "What's the remediation for Log4Shell?",
    "Is there a CVE related to Struts2 RCE in the corpus?",
    "What CVE exists for GhostFrameworkXYZ?",
    "What's the OWASP A03:2025 category about?",
    "What's the most severe vulnerability in the entire corpus?",
]

results = []
for i, q in enumerate(queries, 1):
    retrieved = retrieve(q)
    result = generate_answer(q, retrieved)
    results.append({
        "num": i,
        "query": q,
        "answer": result["answer"],
        "severity": result["severity"],
        "num_sources_used": len(result["sources"]),
        "top_chunk_distances": [c.get("distance") for c in retrieved[:3]],
    })
    print(f"[{i}/15] done")

with open("query_pass_results_v2.json", "w") as f:
    json.dump(results, f, indent=2)

print("done, wrote query_pass_results_v2.json")