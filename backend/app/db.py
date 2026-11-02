"""Centralised config + SQLAlchemy models (SQLite default, Postgres via DATABASE_URL)."""
import os, uuid, logging
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, JSON, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./afraids.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
uid = lambda: str(uuid.uuid4())

class SecurityEvent(Base):
    __tablename__ = "security_events"
    id = Column(String, primary_key=True, default=uid)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source = Column(String); event_type = Column(String, index=True)
    user = Column(String); host = Column(String)
    src_ip = Column(String); dst_ip = Column(String)
    severity = Column(String, default="low"); meta = Column(JSON, default=dict)
    simulation_id = Column(String, index=True)

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True, default=uid)
    title = Column(String); status = Column(String, default="open")
    key = Column(String, index=True)  # correlation key (host|user)
    risk_score = Column(Float, default=0); risk_level = Column(String, default="low")
    techniques = Column(JSON, default=list); created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    risk_factors = Column(JSON, default=list); anomaly_score = Column(Float, default=0)
    # --- Phase 3 (agentic workflow) ---
    state = Column(String, default="RECEIVED")            # IncidentState (agentic/states.py)
    confidence = Column(Float); needs_review = Column(Integer, default=0)
    verdict = Column(String)                               # confirmed | needs_review
    assessment = Column(JSON); iterations = Column(Integer, default=0)
    alerts = relationship("Alert", back_populates="incident")
    recommendations = relationship("ResponseRecommendation", back_populates="incident")

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True, default=uid)
    rule = Column(String); severity = Column(String); technique = Column(String)
    confidence = Column(Float); evidence = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
    incident_id = Column(String, ForeignKey("incidents.id"))
    rule_id = Column(String); points = Column(Integer, default=0); uncertain = Column(Integer, default=0)
    anomaly_score = Column(Float); event_id = Column(String)
    incident = relationship("Incident", back_populates="alerts")

class ResponseRecommendation(Base):
    __tablename__ = "response_recommendations"
    id = Column(String, primary_key=True, default=uid)
    incident_id = Column(String, ForeignKey("incidents.id"))
    action = Column(String); rationale = Column(Text)
    status = Column(String, default="pending")  # pending|approved|rejected
    decided_at = Column(DateTime)
    # --- Phase 3: structured response plan + approval workflow ---
    target = Column(String); params = Column(JSON); expected_impact = Column(Text); confidence = Column(Float)
    approval_level = Column(String)                        # minimum role allowed to approve (None = legacy recommendation)
    destructive = Column(Integer, default=0); created_at = Column(DateTime, default=datetime.utcnow)
    decided_by = Column(String); decision_comment = Column(Text); executed_at = Column(DateTime); execution_result = Column(JSON)
    run_id = Column(String); modified = Column(Integer, default=0); original_action = Column(String)
    incident = relationship("Incident", back_populates="recommendations")

class AgentExecution(Base):
    __tablename__ = "agent_executions"
    id = Column(String, primary_key=True, default=uid)
    agent = Column(String); status = Column(String); confidence = Column(Float)
    started_at = Column(DateTime); finished_at = Column(DateTime)
    output = Column(JSON); evidence = Column(JSON); error = Column(Text)
    # --- Phase 3: full execution record ---
    incident_id = Column(String, index=True); run_id = Column(String, index=True)
    sequence = Column(Integer); iteration = Column(Integer)
    input_summary = Column(Text); output_summary = Column(Text)
    tools_used = Column(JSON); evidence_ids = Column(JSON)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=uid)
    timestamp = Column(DateTime, default=datetime.utcnow)
    actor = Column(String); action = Column(String); detail = Column(JSON)


class Entity(Base):
    __tablename__ = "entities"
    id = Column(String, primary_key=True, default=uid); kind = Column(String, index=True); value = Column(String, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
class IPAddress(Base):
    __tablename__ = "ip_addresses"
    id = Column(String, primary_key=True, default=uid); address = Column(String, unique=True); internal = Column(Integer, default=0)
class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=uid); username = Column(String, unique=True)
class Host(Base):
    __tablename__ = "hosts"
    id = Column(String, primary_key=True, default=uid); hostname = Column(String, unique=True)
class Process(Base):
    __tablename__ = "processes"
    id = Column(String, primary_key=True, default=uid); name = Column(String); host = Column(String)
class AttackTechnique(Base):
    __tablename__ = "attack_techniques"
    technique_id = Column(String, primary_key=True); name = Column(String); tactic = Column(String); description = Column(Text)
class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    id = Column(String, primary_key=True, default=uid); incident_id = Column(String, ForeignKey("incidents.id"))
    event_id = Column(String); alert_id = Column(String); note = Column(Text)
class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    id = Column(String, primary_key=True, default=uid); incident_id = Column(String, ForeignKey("incidents.id"))
    score = Column(Float); level = Column(String); factors = Column(JSON); created_at = Column(DateTime, default=datetime.utcnow)

# ---------------------------------------------------------------- Phase 3 tables
class ToolCall(Base):
    """One row per tool invocation (success or failure) made through the ToolRegistry."""
    __tablename__ = "tool_calls"
    id = Column(String, primary_key=True, default=uid); incident_id = Column(String, index=True); execution_id = Column(String, index=True)
    run_id = Column(String); agent = Column(String); tool = Column(String); input = Column(JSON); output_summary = Column(Text)
    status = Column(String); error = Column(Text); duration_ms = Column(Float); started_at = Column(DateTime, default=datetime.utcnow)

class InvestigationFinding(Base):
    __tablename__ = "investigation_findings"
    id = Column(String, primary_key=True, default=uid); incident_id = Column(String, index=True); execution_id = Column(String, index=True)
    run_id = Column(String); iteration = Column(Integer); description = Column(Text); evidence = Column(JSON)
    severity = Column(String); confidence = Column(Float); source = Column(String); contradicts = Column(Integer, default=0)
    evidence_ids = Column(JSON); created_at = Column(DateTime, default=datetime.utcnow)

class IncidentStateTransition(Base):
    __tablename__ = "incident_state_transitions"
    id = Column(String, primary_key=True, default=uid); incident_id = Column(String, index=True); run_id = Column(String)
    from_state = Column(String); to_state = Column(String); reason = Column(Text); actor = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"
    id = Column(String, primary_key=True, default=uid); incident_id = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow); kind = Column(String); message = Column(Text); detail = Column(JSON)

class SimulatedEffect(Base):
    """State changed by the SimulationResponseExecutor (blocklist, disabled accounts...). Never reflects a real system."""
    __tablename__ = "simulated_effects"
    id = Column(String, primary_key=True, default=uid); incident_id = Column(String, index=True); response_id = Column(String)
    kind = Column(String, index=True); target = Column(String); active = Column(Integer, default=1); detail = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    """Apply Alembic migrations. Pre-migration databases (tables but no alembic_version) are stamped, not recreated."""
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini")); cfg.set_main_option("script_location", os.path.join(os.path.dirname(__file__), "..", "alembic"))
    tables = set(inspect(engine).get_table_names())
    if "security_events" in tables and "alembic_version" not in tables: command.stamp(cfg, "0001")  # pre-migration schema == revision 0001
    command.upgrade(cfg, "head")
