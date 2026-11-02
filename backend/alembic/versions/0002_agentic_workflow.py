"""phase 3: agentic workflow (state machine, tool calls, findings, approvals, simulated effects)
Revision ID: 0002
Revises: 0001

UNVERIFIED: written without being executed. tests/test_agentic.py::test_migration_matches_models checks column drift.
"""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade():
    # --- incidents
    op.add_column('incidents', sa.Column('state', sa.String(), nullable=True, server_default='RECEIVED'))
    op.add_column('incidents', sa.Column('confidence', sa.Float(), nullable=True))
    op.add_column('incidents', sa.Column('needs_review', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('incidents', sa.Column('verdict', sa.String(), nullable=True))
    op.add_column('incidents', sa.Column('assessment', sa.JSON(), nullable=True))
    op.add_column('incidents', sa.Column('iterations', sa.Integer(), nullable=True, server_default='0'))

    # --- agent_executions
    op.add_column('agent_executions', sa.Column('incident_id', sa.String(), nullable=True))
    op.add_column('agent_executions', sa.Column('run_id', sa.String(), nullable=True))
    op.add_column('agent_executions', sa.Column('sequence', sa.Integer(), nullable=True))
    op.add_column('agent_executions', sa.Column('iteration', sa.Integer(), nullable=True))
    op.add_column('agent_executions', sa.Column('input_summary', sa.Text(), nullable=True))
    op.add_column('agent_executions', sa.Column('output_summary', sa.Text(), nullable=True))
    op.add_column('agent_executions', sa.Column('tools_used', sa.JSON(), nullable=True))
    op.add_column('agent_executions', sa.Column('evidence_ids', sa.JSON(), nullable=True))
    op.create_index('ix_agent_executions_incident_id', 'agent_executions', ['incident_id'])
    op.create_index('ix_agent_executions_run_id', 'agent_executions', ['run_id'])

    # --- response_recommendations
    op.add_column('response_recommendations', sa.Column('target', sa.String(), nullable=True))
    op.add_column('response_recommendations', sa.Column('params', sa.JSON(), nullable=True))
    op.add_column('response_recommendations', sa.Column('expected_impact', sa.Text(), nullable=True))
    op.add_column('response_recommendations', sa.Column('confidence', sa.Float(), nullable=True))
    op.add_column('response_recommendations', sa.Column('approval_level', sa.String(), nullable=True))
    op.add_column('response_recommendations', sa.Column('destructive', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('response_recommendations', sa.Column('created_at', sa.DateTime(), nullable=True))
    op.add_column('response_recommendations', sa.Column('decided_by', sa.String(), nullable=True))
    op.add_column('response_recommendations', sa.Column('decision_comment', sa.Text(), nullable=True))
    op.add_column('response_recommendations', sa.Column('executed_at', sa.DateTime(), nullable=True))
    op.add_column('response_recommendations', sa.Column('execution_result', sa.JSON(), nullable=True))
    op.add_column('response_recommendations', sa.Column('run_id', sa.String(), nullable=True))
    op.add_column('response_recommendations', sa.Column('modified', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('response_recommendations', sa.Column('original_action', sa.String(), nullable=True))

    # --- new tables
    op.create_table('tool_calls',
        sa.Column('id', sa.String(), nullable=False), sa.Column('incident_id', sa.String(), nullable=True),
        sa.Column('execution_id', sa.String(), nullable=True), sa.Column('run_id', sa.String(), nullable=True),
        sa.Column('agent', sa.String(), nullable=True), sa.Column('tool', sa.String(), nullable=True),
        sa.Column('input', sa.JSON(), nullable=True), sa.Column('output_summary', sa.Text(), nullable=True),
        sa.Column('status', sa.String(), nullable=True), sa.Column('error', sa.Text(), nullable=True),
        sa.Column('duration_ms', sa.Float(), nullable=True), sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'))
    op.create_index('ix_tool_calls_incident_id', 'tool_calls', ['incident_id'])
    op.create_index('ix_tool_calls_execution_id', 'tool_calls', ['execution_id'])

    op.create_table('investigation_findings',
        sa.Column('id', sa.String(), nullable=False), sa.Column('incident_id', sa.String(), nullable=True),
        sa.Column('execution_id', sa.String(), nullable=True), sa.Column('run_id', sa.String(), nullable=True),
        sa.Column('iteration', sa.Integer(), nullable=True), sa.Column('description', sa.Text(), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=True), sa.Column('severity', sa.String(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True), sa.Column('source', sa.String(), nullable=True),
        sa.Column('contradicts', sa.Integer(), nullable=True), sa.Column('evidence_ids', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True), sa.PrimaryKeyConstraint('id'))
    op.create_index('ix_investigation_findings_incident_id', 'investigation_findings', ['incident_id'])
    op.create_index('ix_investigation_findings_execution_id', 'investigation_findings', ['execution_id'])

    op.create_table('incident_state_transitions',
        sa.Column('id', sa.String(), nullable=False), sa.Column('incident_id', sa.String(), nullable=True),
        sa.Column('run_id', sa.String(), nullable=True), sa.Column('from_state', sa.String(), nullable=True),
        sa.Column('to_state', sa.String(), nullable=True), sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('actor', sa.String(), nullable=True), sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'))
    op.create_index('ix_incident_state_transitions_incident_id', 'incident_state_transitions', ['incident_id'])

    op.create_table('incident_timeline',
        sa.Column('id', sa.String(), nullable=False), sa.Column('incident_id', sa.String(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True), sa.Column('kind', sa.String(), nullable=True),
        sa.Column('message', sa.Text(), nullable=True), sa.Column('detail', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id'))
    op.create_index('ix_incident_timeline_incident_id', 'incident_timeline', ['incident_id'])

    op.create_table('simulated_effects',
        sa.Column('id', sa.String(), nullable=False), sa.Column('incident_id', sa.String(), nullable=True),
        sa.Column('response_id', sa.String(), nullable=True), sa.Column('kind', sa.String(), nullable=True),
        sa.Column('target', sa.String(), nullable=True), sa.Column('active', sa.Integer(), nullable=True),
        sa.Column('detail', sa.JSON(), nullable=True), sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'))
    op.create_index('ix_simulated_effects_incident_id', 'simulated_effects', ['incident_id'])
    op.create_index('ix_simulated_effects_kind', 'simulated_effects', ['kind'])


def downgrade():
    for t in ('simulated_effects', 'incident_timeline', 'incident_state_transitions', 'investigation_findings', 'tool_calls'):
        op.drop_table(t)
    with op.batch_alter_table('response_recommendations') as b:
        for c in ('target', 'params', 'expected_impact', 'confidence', 'approval_level', 'destructive', 'created_at', 'decided_by',
                  'decision_comment', 'executed_at', 'execution_result', 'run_id', 'modified', 'original_action'):
            b.drop_column(c)
    op.drop_index('ix_agent_executions_run_id', table_name='agent_executions')
    op.drop_index('ix_agent_executions_incident_id', table_name='agent_executions')
    with op.batch_alter_table('agent_executions') as b:
        for c in ('incident_id', 'run_id', 'sequence', 'iteration', 'input_summary', 'output_summary', 'tools_used', 'evidence_ids'):
            b.drop_column(c)
    with op.batch_alter_table('incidents') as b:
        for c in ('state', 'confidence', 'needs_review', 'verdict', 'assessment', 'iterations'):
            b.drop_column(c)
