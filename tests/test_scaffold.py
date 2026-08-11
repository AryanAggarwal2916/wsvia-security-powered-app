"""
Placeholder test — just confirms the package structure imports without
error. Replace/expand once real logic exists in each layer.
"""

import importlib

MODULES = [
    "ingestion.loaders",
    "ingestion.chunking",
    "indexing.embeddings",
    "indexing.vector_store",
    "retrieval.retriever",
    "generation.prompts",
    "generation.llm_client",
    "generation.generator",
    "config",
]


def test_all_modules_importable():
    for module_name in MODULES:
        importlib.import_module(module_name)
