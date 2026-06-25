"""
backend/api/main.py
---------------------
FastAPI application entry point for the Local LLM Hunter REST API.

Initialises the database on startup, wires the CORS middleware for
development, and mounts the routes defined in routes.py.

Run with:
    uvicorn backend.api.main:app --reload --port 8000

API docs auto-generated at:
    http://localhost:8000/docs      (Swagger UI)
    http://localhost:8000/redoc     (ReDoc)
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# Project imports with fallback for direct module execution
# ---------------------------------------------------------------------------
try:
    from database        import db as _db
    from backend.api     import routes
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from database        import db as _db
    from backend.api     import routes


# ---------------------------------------------------------------------------
# Lifespan: runs on startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.

    On startup:  initialise the SQLite database (creates tables if absent).
    On shutdown: no-op (sqlite3 connections are closed per-request).
    """
    _db.init_db()
    print("[LocalLLMHunter API] Database initialised.")
    yield
    # Shutdown — nothing to clean up for sqlite3


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title       = "Local LLM Hunter API",
    description = (
        "REST API for the Local LLM Hunter endpoint detection agent. "
        "Provides event ingestion, inventory queries, alert management, "
        "and dashboard statistics for the Shadow AI Governance capstone."
    ),
    version     = "1.0.0",
    lifespan    = lifespan,
)

# ---------------------------------------------------------------------------
# CORS — allow all origins for development
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],   # Restrict to specific origins in production
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ---------------------------------------------------------------------------
# Mount router
# ---------------------------------------------------------------------------

app.include_router(routes.router)
