"""add id_user to Commentaire

Revision ID: f1092b4514b3
Revises: a563c669c3ca
Create Date: 2025-04-15 18:59:48.767467

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f1092b4514b3'
down_revision = 'a563c669c3ca'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('commentaires', schema=None) as batch_op:
        batch_op.add_column(sa.Column('id_user', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            'fk_commentaires_id_user', 
            'users', 
            ['id_user'], 
            ['id']
        )


    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('commentaires', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('id_user')

    # ### end Alembic commands ###
