import os, tempfile
d = tempfile.mkdtemp(); os.environ["DATABASE_URL"] = f"sqlite:///{d}/t.db"; os.environ["MODEL_PATH"] = f"{d}/m.joblib"
import pytest
from datetime import datetime, timedelta
from app.db import SessionLocal, SecurityEvent, init_db
init_db(); T0 = datetime(2026, 1, 1, 12, 0, 0)

@pytest.fixture
def db():
    with SessionLocal() as s: yield s

def ev(db, t, mins=0, user="u1", host="h1", src="10.0.0.9", dst="10.0.0.5", **meta):
    e = SecurityEvent(event_type=t, timestamp=T0 + timedelta(minutes=mins), user=user, host=host, src_ip=src, dst_ip=dst, meta=meta, severity="low", source="test")
    db.add(e); db.flush(); return e
