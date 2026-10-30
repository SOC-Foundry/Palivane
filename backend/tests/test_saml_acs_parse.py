"""process_acs against the real python3-saml return shapes (QA H7).

Every other SAML test replaces process_acs whole, so this code never ran under test:
get_last_assertion_not_on_or_after() returns one int, and process_acs took max() of it,
which raised TypeError and turned every SAML sign-in into a 500.
"""

from __future__ import annotations

import pytest

from app import saml


class _Auth:
    def __init__(self, noa):
        self._noa = noa

    def process_response(self, request_id=None):
        pass

    def get_errors(self):
        return []

    def is_authenticated(self):
        return True

    def get_attributes(self):
        return {"email": ["sso-user@acme.com"]}

    def get_nameid(self):
        return "sso-user@acme.com"

    def get_last_assertion_id(self):
        return "_assert_1"

    def get_last_assertion_not_on_or_after(self):
        return self._noa


@pytest.mark.parametrize("noa,want", [(1893456000, 1893456000), (None, 0), (0, 0),
                                      ([1893456000, 1893456600], 1893456600), ([], 0)])
def test_process_acs_reads_not_on_or_after(monkeypatch, noa, want):
    monkeypatch.setattr(saml, "_auth", lambda *a, **k: _Auth(noa))
    out = saml.process_acs({}, None, "sp", "https://sp/acs")
    assert out["email"] == "sso-user@acme.com" and out["assertion_id"] == "_assert_1"
    assert out["not_on_or_after"] == want


def test_the_library_returns_an_int():
    # The shape this depends on, pinned: OneLogin_Saml2_Response stores the parsed time,
    # an int from parse_SAML_to_time, and Auth hands it back unchanged.
    from onelogin.saml2.utils import OneLogin_Saml2_Utils
    assert isinstance(OneLogin_Saml2_Utils.parse_SAML_to_time("2030-01-01T00:00:00Z"), int)
