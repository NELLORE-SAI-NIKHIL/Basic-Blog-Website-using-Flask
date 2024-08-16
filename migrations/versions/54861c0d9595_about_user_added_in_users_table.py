"""About User added in Users Table

Revision ID: 54861c0d9595
Revises: 8e6a9935de09
Create Date: 2024-06-29 00:42:22.164835

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '54861c0d9595'
down_revision = '8e6a9935de09'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('about_user', sa.Text(length=500), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('about_user')

    # ### end Alembic commands ###
