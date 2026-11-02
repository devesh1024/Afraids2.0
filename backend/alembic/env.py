import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from alembic import context
from app.db import Base, engine
target_metadata = Base.metadata
def run_migrations_online():
    with engine.connect() as c:
        context.configure(connection=c, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction(): context.run_migrations()
run_migrations_online()
