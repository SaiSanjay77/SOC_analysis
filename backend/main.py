"""
Unified SOC-AML Risk Engine — FastAPI Application Entry Point

SQLite-only mode for hackathon prototype.
No Neo4j dependency required.
"""

import logging
import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import init_db

load_dotenv()

# ── Logging ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-28s │ %(levelname)-7s │ %(message)s",
)
logger = logging.getLogger("soc_aml")


# ── Lifespan ─────────────────────────────────────────────────────
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown."""
    logger.info("Initialising SQLite database...")
    init_db()
    logger.info("SQLite database ready (soc_aml.db)")

    # Legacy graph layer — kept for /api/v1/graph-data backwards compat
    try:
        from graph_layer.mock_driver import MockNeo4jDriver
        from graph_layer.schema import initialize_schema
        from graph_layer.ingestion import ingest_data
        from pathlib import Path
        import json

        driver = MockNeo4jDriver()
        initialize_schema(driver)

        sample_path = Path(__file__).parent / "graph_layer" / "sample_data.json"
        if sample_path.exists():
            with open(sample_path, "r", encoding="utf-8") as f:
                sample = json.load(f)
            ingest_data(driver, sample)

        app.state.driver = driver
        app.state.store = driver.store
        logger.info("Graph layer loaded (mock mode for legacy endpoints)")
    except Exception as e:
        logger.warning("Graph layer unavailable: %s", e)
        app.state.driver = None
        app.state.store = None

    yield

    if getattr(app.state, "driver", None):
        app.state.driver.close()
        logger.info("Graph driver closed")


# ── FastAPI Application ─────────────────────────────────────────
app = FastAPI(
    title="Unified SOC-AML Risk Engine API",
    description=(
        "Indian financial context SOC-AML risk engine. "
        "SQLite database with INR, UPI, IMPS, NEFT support."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ─────────────────────────────────────────────────────
# Primary SQL-backed routers
from routers import db_threats, analyze, sandbox, bank_portal, bank_server
app.include_router(db_threats.router)
app.include_router(analyze.router)
app.include_router(sandbox.router)
app.include_router(bank_portal.router)
app.include_router(bank_server.router)

# Legacy graph routers (optional, for backwards compat)
try:
    from routers import ingest, graph_data, threat_intel
    app.include_router(ingest.router)
    app.include_router(graph_data.router)
    app.include_router(threat_intel.router)
except Exception:
    pass


# ── Health check ────────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    return {
        "service": "Unified SOC-AML Risk Engine",
        "status": "operational",
        "version": "2.0.0",
        "database": "SQLite (soc_aml.db)",
        "locale": "IN (INR)",
        "docs": "/docs",
    }
