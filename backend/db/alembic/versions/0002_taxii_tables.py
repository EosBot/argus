"""TAXII collections and objects tables.

Revision ID: 0002_taxii_tables
Revises: 0001_initial
Create Date: 2026-08-13 06:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision: str = "0002_taxii_tables"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create taxii_collections and taxii_objects tables."""

    # -- TAXII Collections table -----------------------------------------------
    op.create_table(
        "taxii_collections",
        sa.Column("id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("can_read", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("can_write", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "media_types",
            sa.ARRAY(sa.Text()),
            nullable=False,
            server_default="{application/stix+json;version=2.1}",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # -- TAXII Objects table ---------------------------------------------------
    op.create_table(
        "taxii_objects",
        sa.Column("id", sa.Text(), primary_key=True, nullable=False),
        sa.Column(
            "collection_id",
            sa.Uuid(),
            sa.ForeignKey("taxii_collections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("created", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("object", sa.JSON(), nullable=False),
        sa.Column(
            "date_added",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "idx_taxii_objects_collection", "taxii_objects", ["collection_id"],
    )
    op.create_index(
        "idx_taxii_objects_type", "taxii_objects", ["type"],
    )
    op.create_index(
        "idx_taxii_objects_date", "taxii_objects", ["date_added"],
    )


def downgrade() -> None:
    """Drop taxii_collections and taxii_objects tables."""
    op.drop_index("idx_taxii_objects_date", table_name="taxii_objects")
    op.drop_index("idx_taxii_objects_type", table_name="taxii_objects")
    op.drop_index("idx_taxii_objects_collection", table_name="taxii_objects")
    op.drop_table("taxii_objects")

    op.drop_table("taxii_collections")
