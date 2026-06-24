"""
workflow — conditional, caching, dependency-aware orchestrator that replaces
pipeline.py's fixed linear funnel. Imports scanner_module's existing
scanner/* classes as-is; never modifies them.
"""
