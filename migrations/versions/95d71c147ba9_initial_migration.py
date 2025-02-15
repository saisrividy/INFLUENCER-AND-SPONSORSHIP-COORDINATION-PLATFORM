"""Initial migration.

Revision ID: 95d71c147ba9
Revises: 
Create Date: 2024-07-30 19:53:54.836823

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '95d71c147ba9'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password_hash', sa.String(length=120), nullable=False),
    sa.Column('role', sa.String(length=10), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    op.create_table('campaign',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('start_date', sa.Date(), nullable=False),
    sa.Column('end_date', sa.Date(), nullable=False),
    sa.Column('budget', sa.Float(), nullable=False),
    sa.Column('visibility', sa.String(length=10), nullable=False),
    sa.Column('goals', sa.Text(), nullable=True),
    sa.Column('sponsor_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['sponsor_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('ad_request',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('campaign_id', sa.Integer(), nullable=False),
    sa.Column('influencer_id', sa.Integer(), nullable=False),
    sa.Column('messages', sa.Text(), nullable=True),
    sa.Column('requirements', sa.Text(), nullable=False),
    sa.Column('payment_amount', sa.Float(), nullable=False),
    sa.Column('status', sa.String(length=10), nullable=False),
    sa.ForeignKeyConstraint(['campaign_id'], ['campaign.id'], ),
    sa.ForeignKeyConstraint(['influencer_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('ad_request')
    op.drop_table('campaign')
    op.drop_table('user')
    # ### end Alembic commands ###
