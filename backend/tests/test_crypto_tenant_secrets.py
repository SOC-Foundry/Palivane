"""Per-tenant secret envelope: enc:v2: under a tenant DEK, with the two legacy shapes
still readable, because migration is lazy (a value is only rewritten when next saved)."""
from __future__ import annotations

from app import crypto


def test_seal_secret_round_trips_under_a_tenant_dek():
    dek = crypto.new_dek()
    tok = crypto.seal_secret(dek, "sk-live-abc123")
    assert tok.startswith("enc:v2:")
    assert "sk-live-abc123" not in tok
    assert crypto.unseal_secret(tok, dek) == "sk-live-abc123"


def test_a_different_tenants_dek_cannot_open_it():
    """The whole point: one tenant's key must not decrypt another's credential."""
    mine, theirs = crypto.new_dek(), crypto.new_dek()
    tok = crypto.seal_secret(mine, "service-account-json")
    assert crypto.unseal_secret(tok, theirs) == ""      # "not configured", never a marker
    assert crypto.unseal_secret(tok, None) == ""


def test_legacy_bare_and_v1_values_still_open():
    """Columns written before this existed hold a bare Fernet token (encrypt()) or an
    enc:v1: value (seal()). Both must keep working with or without a DEK present."""
    bare = crypto.encrypt("old-provider-key")
    assert not bare.startswith("enc:")
    v1 = crypto.seal("old-siem-token")
    assert v1.startswith("enc:v1:")
    for dek in (None, crypto.new_dek()):
        assert crypto.unseal_secret(bare, dek) == "old-provider-key"
        assert crypto.unseal_secret(v1, dek) == "old-siem-token"


def test_no_dek_falls_back_to_the_global_key():
    tok = crypto.seal_secret(None, "fallback")
    assert not tok.startswith("enc:v2:")
    assert crypto.unseal_secret(tok, None) == "fallback"


def test_empty_and_non_string_are_passed_through_as_unconfigured():
    assert crypto.seal_secret(crypto.new_dek(), "") == ""
    assert crypto.unseal_secret("", None) == ""
    assert crypto.unseal_secret(None, None) == ""


def test_garbage_reads_as_unconfigured_rather_than_raising():
    """A rotated KEK leaves undecryptable rows; callers treat "" as not configured."""
    assert crypto.unseal_secret("enc:v2:not-a-token", crypto.new_dek()) == ""
    assert crypto.unseal_secret("enc:v1:not-a-token", None) == ""


def test_readonly_unwrap_matches_the_provisioning_path():
    """Background paths open an existing DEK without a session; it must be the same key."""
    class T:
        dek_wrapped = ""
    t = T()
    dek = crypto.new_dek()
    t.dek_wrapped = crypto.wrap_dek(dek)
    assert crypto.tenant_dek_readonly(t) == dek
    tok = crypto.seal_secret(dek, "s3-secret")
    assert crypto.unseal_secret(tok, crypto.tenant_dek_readonly(t)) == "s3-secret"


def test_readonly_unwrap_is_none_before_a_dek_exists():
    class T:
        dek_wrapped = ""
    assert crypto.tenant_dek_readonly(T()) is None
    assert crypto.tenant_dek_readonly(None) is None
