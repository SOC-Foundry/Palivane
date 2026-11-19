"""IdP group mappings, SCIM groups, and the directory team on users.

Revision ID: 62b62c30efd5
Revises: 3d68f59e9ec9
Create Date: 2026-11-18

"""
from alembic import op
import sqlalchemy as sa

revision = "62b62c30efd5"
down_revision = "3d68f59e9ec9"
branch_labels = None
depends_on = None

# Same predicate as a9f1c3e5b7d0 (copied: a migration must not change if that file is
# edited). Falls open when app.tenant_id is unset, so pre-auth lookups keep working.
# Fails closed, as c8f1a3e5b7d9 made every tenant policy: a bound tenant sees its rows and
# the NULL-tenant globals; app.cross_tenant='on' (database.allow_cross_tenant) sees all;
# an unbound session sees nothing.
_PREDICATE = (
    "current_setting('app.cross_tenant', true) = 'on' "
    "OR ("
    " COALESCE(current_setting('app.tenant_id', true), '') <> '' "
    " AND (tenant_id IS NULL "
    " OR tenant_id::text = current_setting('app.tenant_id', true))"
    ")"
)
_RLS_TABLES = ("group_mappings", "scim_groups", "scim_group_members")


def upgrade():
    op.add_column("users", sa.Column("team", sa.String(length=128), nullable=False, server_default=""))
    op.add_column("users", sa.Column("group_sources", sa.JSON(), nullable=True))
    op.add_column("users", sa.Column(
        "role_from_groups", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        "group_mappings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("group_key", sa.String(length=512), nullable=False),
        sa.Column("label", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="member"),
        sa.Column("team", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("tenant_id", "group_key", name="uq_groupmap_tenant_key"),
    )
    op.create_index("ix_group_mappings_id", "group_mappings", ["id"])
    op.create_index("ix_group_mappings_tenant_id", "group_mappings", ["tenant_id"])
    op.create_table(
        "scim_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("display_name", sa.String(length=512), nullable=False),
        sa.Column("external_id", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("tenant_id", "display_name", name="uq_scimgroup_tenant_name"),
    )
    op.create_index("ix_scim_groups_id", "scim_groups", ["id"])
    op.create_index("ix_scim_groups_tenant_id", "scim_groups", ["tenant_id"])
    op.create_table(
        "scim_group_members",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("group_id", sa.Integer(), sa.ForeignKey("scim_groups.id"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.UniqueConstraint("group_id", "user_id", name="uq_scim_member"),
    )
    op.create_index("ix_scim_group_members_id", "scim_group_members", ["id"])
    op.create_index("ix_scim_group_members_tenant_id", "scim_group_members", ["tenant_id"])
    op.create_index("ix_scim_group_members_group_id", "scim_group_members", ["group_id"])
    op.create_index("ix_scim_group_members_user_id", "scim_group_members", ["user_id"])
    if op.get_bind().dialect.name != "postgresql":
        return
    for t in _RLS_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {t} "
            f"USING ({_PREDICATE}) WITH CHECK ({_PREDICATE})"
        )


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        for t in _RLS_TABLES:
            op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
            op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_scim_group_members_user_id", table_name="scim_group_members")
    op.drop_index("ix_scim_group_members_group_id", table_name="scim_group_members")
    op.drop_index("ix_scim_group_members_tenant_id", table_name="scim_group_members")
    op.drop_table("scim_group_members")
    op.drop_index("ix_scim_groups_tenant_id", table_name="scim_groups")
    op.drop_table("scim_groups")
    op.drop_index("ix_group_mappings_tenant_id", table_name="group_mappings")
    op.drop_table("group_mappings")
    op.drop_column("users", "role_from_groups")
    op.drop_column("users", "group_sources")
    op.drop_column("users", "team")
