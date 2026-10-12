"""Initial MySQL database migration for NetSential SOC

Revision ID: 0001_initial_tables
Revises: 
Create Date: 2026-10-12 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0001_initial_tables'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # 1. users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('email', sa.String(length=120), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=20), server_default='analyst', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='1', nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index('idx_users_role', 'users', ['role'], unique=False)
    op.create_index('idx_users_is_active', 'users', ['is_active'], unique=False)

    # 2. upload_batches table
    op.create_table(
        'upload_batches',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('original_filename', sa.String(length=255), nullable=False),
        sa.Column('uploaded_by', sa.Integer(), nullable=True),
        sa.Column('total_rows', sa.Integer(), server_default='0', nullable=False),
        sa.Column('accepted_rows', sa.Integer(), server_default='0', nullable=False),
        sa.Column('rejected_rows', sa.Integer(), server_default='0', nullable=False),
        sa.Column('status', sa.String(length=30), server_default='completed', nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )

    # 3. security_events table
    op.create_table(
        'security_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('source_ip', sa.String(length=45), nullable=False),
        sa.Column('username', sa.String(length=64), nullable=True),
        sa.Column('status', sa.String(length=30), server_default='failure', nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('event_time', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('upload_batch_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['upload_batch_id'], ['upload_batches.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_security_events_event_type'), 'security_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_security_events_source_ip'), 'security_events', ['source_ip'], unique=False)
    op.create_index(op.f('ix_security_events_username'), 'security_events', ['username'], unique=False)
    op.create_index(op.f('ix_security_events_severity'), 'security_events', ['severity'], unique=False)
    op.create_index(op.f('ix_security_events_event_time'), 'security_events', ['event_time'], unique=False)
    op.create_index(op.f('ix_security_events_upload_batch_id'), 'security_events', ['upload_batch_id'], unique=False)

    # 4. alerts table
    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('event_id', sa.Integer(), nullable=False),
        sa.Column('rule_code', sa.String(length=32), nullable=False),
        sa.Column('title', sa.String(length=150), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='NEW', nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['event_id'], ['security_events.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('event_id', 'rule_code', name='uq_alert_event_rule')
    )
    op.create_index(op.f('ix_alerts_event_id'), 'alerts', ['event_id'], unique=False)
    op.create_index(op.f('ix_alerts_rule_code'), 'alerts', ['rule_code'], unique=False)
    op.create_index(op.f('ix_alerts_severity'), 'alerts', ['severity'], unique=False)
    op.create_index(op.f('ix_alerts_status'), 'alerts', ['status'], unique=False)

    # 5. audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'], unique=False)
    op.create_index(op.f('ix_audit_logs_user_id'), 'audit_logs', ['user_id'], unique=False)


def downgrade():
    op.drop_table('audit_logs')
    op.drop_table('alerts')
    op.drop_table('security_events')
    op.drop_table('upload_batches')
    op.drop_table('users')
