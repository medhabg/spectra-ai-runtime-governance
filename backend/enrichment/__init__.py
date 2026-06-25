# backend/enrichment/__init__.py
# Exposes the EnrichmentEngine for import from the backend.enrichment package.

from .enrichment_engine import EnrichmentEngine

__all__ = ["EnrichmentEngine"]
