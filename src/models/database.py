"""
SQLAlchemy models and database initialization for AI AppSec Service.
Uses SQLite for the alpha version.

Models:
  - User: local auth with role-based access
  - ScanRequest: intake form submissions (linked to requester user)
  - ScanRun: one execution of the full SAST+DAST pipeline
  - Finding: normalised finding from any engine, with status workflow
  - Certification: issued by Scanner team when all findings resolved
"""

import datetime
import hashlib
import secrets
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, Boolean, create_engine
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()

# ---------------------------------------------------------------------------
# User – local authentication with role-based access control
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(200), unique=True, nullable=False)
    display_name = Column(String(200), nullable=False)
    password_hash = Column(String(256), nullable=False)
    password_salt = Column(String(64), nullable=False)
    role = Column(String(20), nullable=False, default="requester")  # requester | scanner | executive | admin
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime, nullable=True)

    # relationships
    scan_requests = relationship("ScanRequest", back_populates="requester_user")

    def set_password(self, password: str):
        """Hash password with salt."""
        self.password_salt = secrets.token_hex(32)
        self.password_hash = hashlib.sha256(
            (password + self.password_salt).encode()
        ).hexdigest()

    def check_password(self, password: str) -> bool:
        """Verify password."""
        return hashlib.sha256(
            (password + self.password_salt).encode()
        ).hexdigest() == self.password_hash


# ---------------------------------------------------------------------------
# Session – server-side session tokens
# ---------------------------------------------------------------------------

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String(128), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)

    user = relationship("User")

    @staticmethod
    def generate_token() -> str:
        return secrets.token_hex(64)


# ---------------------------------------------------------------------------
# ScanRequest – one row per intake form submission
# ---------------------------------------------------------------------------

class ScanRequest(Base):
    __tablename__ = "scan_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    requester_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
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
    requester_user = relationship("User", back_populates="scan_requests")
    scan_runs = relationship("ScanRun", back_populates="scan_request", cascade="all, delete-orphan")
    certifications = relationship("Certification", back_populates="scan_request", cascade="all, delete-orphan")


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
    initiated_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # Scanner who triggered

    # relationships
    scan_request = relationship("ScanRequest", back_populates="scan_runs")
    findings = relationship("Finding", back_populates="scan_run", cascade="all, delete-orphan")
    initiator = relationship("User", foreign_keys=[initiated_by])


# ---------------------------------------------------------------------------
# Finding – one normalised finding from any engine, with status workflow
# Status workflow: Open → Fixed → Verified → Closed
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
    short_title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    location = Column(String(500), nullable=True)       # file:line or URL
    evidence_snippet = Column(Text, nullable=True)      # short code/response excerpt

    # Status workflow
    status = Column(String(20), nullable=False, default="open")  # open | fixed | verified | closed
    status_updated_at = Column(DateTime, nullable=True)
    status_updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    fix_notes = Column(Text, nullable=True)             # requester's notes when marking fixed
    verification_notes = Column(Text, nullable=True)    # scanner's notes when verifying

    # relationships
    scan_run = relationship("ScanRun", back_populates="findings")
    status_updater = relationship("User", foreign_keys=[status_updated_by])


# ---------------------------------------------------------------------------
# Certification – issued by Scanner when all findings are closed
# ---------------------------------------------------------------------------

class Certification(Base):
    __tablename__ = "certifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_request_id = Column(Integer, ForeignKey("scan_requests.id"), nullable=False)
    issued_at = Column(DateTime, default=datetime.datetime.utcnow)
    issued_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    cert_type = Column(String(50), nullable=False, default="security_clearance")
    notes = Column(Text, nullable=True)
    valid_until = Column(DateTime, nullable=True)       # optional expiry

    # relationships
    scan_request = relationship("ScanRequest", back_populates="certifications")
    issuer = relationship("User", foreign_keys=[issued_by])


# ---------------------------------------------------------------------------
# Database setup helpers
# ---------------------------------------------------------------------------

DATABASE_URL = "sqlite:///ai_appsec.db"

engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)

    # Seed default admin user if no users exist
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            admin = User(
                username="admin",
                email="admin@mastek.com",
                display_name="System Admin",
                role="admin",
            )
            admin.set_password("admin123")

            scanner = User(
                username="scanner",
                email="siddharth.venkataraman@mastek.com",
                display_name="Siddharth V",
                role="scanner",
            )
            scanner.set_password("scanner123")

            requester = User(
                username="requester",
                email="requester@mastek.com",
                display_name="Demo Requester",
                role="requester",
            )
            requester.set_password("requester123")

            executive = User(
                username="executive",
                email="executive@mastek.com",
                display_name="Demo Executive",
                role="executive",
            )
            executive.set_password("executive123")

            db.add_all([admin, scanner, requester, executive])
            db.commit()
    finally:
        db.close()


def get_db():
    """Dependency for FastAPI routes – yields a session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
