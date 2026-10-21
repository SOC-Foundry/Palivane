"""Every table with a tenant_id is under Row-Level Security.

The RLS policies live in migrations, not in the models, so adding a tenant-scoped table
and forgetting the policy is silent: the app-level filters still work, every test passes,
and the database-level isolation /trust promises simply does not apply to that table.
That happened to seven tables (fixed by f758200a1b4b). This test makes it loud.

It replays the upgrade() of every migration that mentions RLS against a recording `op`
that reports a Postgres dialect, collects the tables whose RLS ends up ENABLEd + FORCEd
with a tenant_isolation policy, and compares that against the ORM. Runs on SQLite — no
database needed. test_rls.py (CI `rls` job) is the one that proves the policies WORK.
"""
import importlib.util
import pathlib
import re
from unittest import mock

from app import models  # noqa: F401 — registers every table on Base.metadata
from app.database import Base

VERSIONS = pathlib.Path(__file__).resolve().parents[1] / "migrations" / "versions"


def _load(path):
    spec = importlib.util.spec_from_file_location(f"_mig_{path.stem}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ordered_rls_migrations():
    mods = {}
    for path in VERSIONS.glob("*.py"):
        if "ROW LEVEL SECURITY" in path.read_text():
            mod = _load(path)
            mods[mod.revision] = mod
    # Order by the revision chain so a later DISABLE wins over an earlier ENABLE.
    every = {}
    for path in VERSIONS.glob("*.py"):
        text = path.read_text()
        rev = re.search(r"^revision[^=]*=\s*['\"](\w+)", text, re.M).group(1)
        down = re.search(r"^down_revision[^=]*=\s*(.+)$", text, re.M).group(1)
        every[rev] = re.findall(r"['\"](\w+)['\"]", down)
    depth = {}

    def _depth(r):
        if r not in depth:
            depth[r] = 1 + max((_depth(d) for d in every.get(r, []) if d in every), default=0)
        return depth[r]

    return [mods[r] for r in sorted(mods, key=_depth)]


def _rls_tables():
    state = {}  # table -> set of {"enable", "force", "policy"}
    for mod in _ordered_rls_migrations():
        sql = []
        op = mock.MagicMock()
        op.get_bind.return_value.dialect.name = "postgresql"
        op.execute.side_effect = lambda s, *a, **k: sql.append(str(s))
        with mock.patch.object(mod, "op", op):
            mod.upgrade()
        for s in sql:
            s = " ".join(s.split())
            if m := re.match(r"ALTER TABLE (\w+) ENABLE ROW LEVEL SECURITY", s):
                state.setdefault(m[1], set()).add("enable")
            elif m := re.match(r"ALTER TABLE (\w+) FORCE ROW LEVEL SECURITY", s):
                state.setdefault(m[1], set()).add("force")
            elif m := re.match(r"CREATE POLICY tenant_isolation ON (\w+)", s):
                state.setdefault(m[1], set()).add("policy")
            elif m := re.match(r"ALTER TABLE (\w+) (?:DISABLE|NO FORCE) ROW LEVEL SECURITY", s):
                state.pop(m[1], None)
    return {t for t, f in state.items() if f == {"enable", "force", "policy"}}


def test_every_tenant_scoped_table_has_rls():
    tenant_tables = {t.name for t in Base.metadata.tables.values() if "tenant_id" in t.c}
    missing = sorted(tenant_tables - _rls_tables())
    assert not missing, (
        f"tables with tenant_id but no RLS policy: {missing}. Add a migration applying the "
        "tenant_isolation policy (see f758200a1b4b_rls_remaining_tenant_tables.py)."
    )


def test_policy_list_has_no_stale_tables():
    # A renamed/dropped table left in an RLS list would make the migration fail on Postgres.
    assert _rls_tables() <= set(Base.metadata.tables)


def test_new_rls_migration_downgrade_reverses_upgrade():
    mod = _load(next(VERSIONS.glob("f758200a1b4b_*.py")))
    sql = []
    op = mock.MagicMock()
    op.get_bind.return_value.dialect.name = "postgresql"
    op.execute.side_effect = lambda s, *a, **k: sql.append(str(s))
    with mock.patch.object(mod, "op", op):
        mod.downgrade()
    for t in mod.TABLES:
        assert f"DROP POLICY IF EXISTS tenant_isolation ON {t}" in sql
        assert f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY" in sql


def test_rls_migrations_are_noops_on_sqlite():
    for mod in _ordered_rls_migrations():
        if mod.revision != "f758200a1b4b":
            continue
        op = mock.MagicMock()
        op.get_bind.return_value.dialect.name = "sqlite"
        with mock.patch.object(mod, "op", op):
            mod.upgrade()
            mod.downgrade()
        op.execute.assert_not_called()
