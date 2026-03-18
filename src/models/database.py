"""
SQLAlchemy models and database initialization for AI AppSec Service.
Uses SQLite for the alpha version.
"""

import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, Enum, create_engine
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()

# ---------------------------------------------------------------------------
# ScanRequest – one row per intake form submission
# ---------------------------------------------------------------------------

class ScanRequest(Base):
    __tablename__ = "scan_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    requester_name = Column(String(200), nullable=False)
    team = Column(String(200), nullable=False)
    email = Column(String(200), nullable=False)
    app_name = Column(String(300), nullable=False)
    description = Column(Text, nullable=True)
    repo_url = Column(String(500), nullable=False)
    branch = Column(String(200), nullable=False)
    env_base_url = Column(String(500), nullable=True)
    llm_usage = Column(Text, nullable=True)         # free text: how the app uses LLMs
    data_profile = Column(Text, nullable=True)       # sensitivity / data types handled

    # relationships
    scan_runs = relationship("ScanRun", back_populates="scan_request", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# ScanRun – one execution of the full SAST+DAST pipeline
# ---------------------------------------------------------------------------

class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_request_id = Column(Integer, ForeignKey("scan_requests.id"), nullable=False)
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(50), default="pending")   # pending | running | completed | failed
    engine_versions = Column(Text, nullable=True)     # JSON string of tool versions

    # relationships
    scan_request = relationship("ScanRequest", back_populates="scan_runs")
    findings = relationship("Finding", back_populates="scan_run", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# Finding – one normalised finding from any engine
# ---------------------------------------------------------------------------

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)

    severity = Column(String(10), nullable=False)       # P1 | P2 | P3
    category = Column(String(50), nullable=False)       # Traditional | AI/LLM
    risk_type = Column(String(200), nullable=False)     # e.g. "SQL injection", "Prompt injection"
    owasp_llm_id = Column(String(20), nullable=True)    # e.g. LLM01, LLM06 or null
    control_id = Column(String(50), nullable=True)      # e.g. PR-LLM-03, TRAD-WEB-01
    source = Column(String(50), default="Unknown")      # Human | Computer | Unknown

    short_title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    location = Column(String(500), nullable=True)       # file:line or URL
    evidence_snippet = Column(Text, nullable=True)      # short code/response excerpt

    # relationships
    scan_run = relationship("ScanRun", back_populates="findings")


# ---------------------------------------------------------------------------
# Database setup helpers
# ---------------------------------------------------------------------------

DATABASE_URL = "sqlite:///ai_appsec.db"

engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Dependency for FastAPI routes – yields a session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
