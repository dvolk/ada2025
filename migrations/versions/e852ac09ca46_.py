"""empty message

Revision ID: e852ac09ca46
Revises: f8f34ceb764c
Create Date: 2023-09-06 16:15:03.835442

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e852ac09ca46'
down_revision = 'f8f34ceb764c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('otp_secret', sa.String(length=32), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('otp_secret')

    # ### end Alembic commands ###