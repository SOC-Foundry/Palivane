"""OAuth sign-in's one-time values are not secrets; the reusable credentials beside them are.
Tokens are generated at runtime."""
from __future__ import annotations

import secrets
import string

from app.detectors.patterns import find_high_entropy_tokens


def _tok(n=40):
    al = string.ascii_letters + string.digits
    while True:
        t = "".join(secrets.choice(al) for _ in range(n))
        if any(c.isdigit() for c in t) and any(c.islower() for c in t) and any(c.isupper() for c in t):
            return t


EXT = "https%3A%2F%2Ffcoeoabgfenejglbffodgkkbkcdhcgfn.chromiumapp.org%2F"


def test_token_exchange_code_is_not_flagged():
    body = (f"grant_type=authorization_code&client_id=dae2cad8-15c5-43d2-9046-fcaecc135fa4"
            f"&code={_tok()}&redirect_uri={EXT}&code_verifier={_tok(64)}")
    assert find_high_entropy_tokens(body) == []


def test_redirect_with_code_and_state_is_not_flagged():
    url = f"https://app.example.com/callback?code={_tok()}&state={_tok(32)}&session_state={_tok(30)}"
    assert find_high_entropy_tokens(url + "&client_id=abc") == []


def test_json_exchange_is_not_flagged():
    body = '{"grant_type": "authorization_code", "code": "%s", "redirect_uri": "x"}' % _tok()
    assert find_high_entropy_tokens(body) == []


def test_reusable_credentials_in_the_same_request_still_flag():
    body = (f"grant_type=authorization_code&client_id=abc&code={_tok()}"
            f"&client_secret={_tok()}&redirect_uri={EXT}")
    assert len(find_high_entropy_tokens(body)) == 1          # the client_secret, not the code
    refresh = f"grant_type=refresh_token&client_id=abc&refresh_token={_tok()}"
    assert len(find_high_entropy_tokens(refresh)) == 1


def test_a_code_field_without_oauth_context_still_flags():
    assert len(find_high_entropy_tokens(f"debug dump: code={_tok()}")) == 1
