"""OAuth consent: the step that decides whose data a token may read.

Why this exists as a bespoke endpoint rather than a page the SDK serves.

OAuth's authorize step is a browser NAVIGATION. The console keeps its session in
localStorage, not a cookie, so a browser arriving at /api/oauth/authorize carries no
identity whatsoever — it is anonymous however thoroughly the user is signed in. The SPA is
the only thing that holds the JWT, so the provider redirects there, the SPA renders consent,
and the approval comes back here with `Authorization: Bearer <console session>`.

Which means every OAuth parameter — client_id, redirect_uri, code_challenge, state — makes a
round trip through a URL in a browser the user might not control. All of it is re-validated
here, from scratch, against the registered client. Nothing that arrives in this request is
trusted because it was in the URL the provider generated; it is trusted only if it still
matches what was registered.

The user identity is the one thing NOT taken from the request body: it comes from the
verified session token. A request cannot name whose data it wants.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .auth import get_current_user
from .database import get_db
from .models import OAuthClient, OAuthCode, User
from .oauth_provider import CODE_TTL, READ_SCOPE, _now, valid_redirect_uri
from .schemas import OAuthConsentRequest
from .security import hash_token

router = APIRouter(prefix="/api/oauth", tags=["oauth"])


@router.get("/pending")
def pending_consent(client_id: str, redirect_uri: str,
                    current: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    """What the consent screen should say — resolved server-side, not from the URL.

    The SPA must not render the client name out of its own query string: that string came
    from whoever sent the user here, and "Palivane Official" is a trivial thing to put in a
    URL. The name shown is the one recorded at registration, looked up by client_id.
    """
    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).one_or_none()
    if client is None:
        raise HTTPException(status_code=404, detail="unknown client")
    if (redirect_uri not in [u for u in (client.redirect_uris or "").split("\n") if u]
            or not valid_redirect_uri(redirect_uri)):
        # Same refusal as consent itself: if the redirect does not match, there is nothing
        # safe to show, because approving would send the code somewhere unregistered.
        raise HTTPException(status_code=400, detail="redirect_uri is not registered for this client")
    return {
        "client_name": client.client_name or client.client_id,
        "client_id": client.client_id,
        "redirect_uri": redirect_uri,
        "scope": READ_SCOPE,
        "scope_description": "Read your Palivane findings, inventory and reports. "
                             "It cannot change anything, and it can only see what you can see.",
        "granting_as": {"email": current.email, "role": current.role},
    }


@router.post("/consent")
def grant_consent(body: OAuthConsentRequest,
                  current: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    """Approve, and mint a one-time code bound to the signed-in user.

    Everything is re-checked here rather than trusted from the authorize redirect.
    """
    client = (db.query(OAuthClient)
                .filter(OAuthClient.client_id == body.client_id).one_or_none())
    if client is None:
        raise HTTPException(status_code=404, detail="unknown client")

    registered = [u for u in (client.redirect_uris or "").split("\n") if u]
    if body.redirect_uri not in registered:
        # EXACT match, never a prefix. This is the check that stops an approved code being
        # delivered to an attacker's callback.
        raise HTTPException(status_code=400,
                            detail="redirect_uri is not registered for this client")
    if not valid_redirect_uri(body.redirect_uri):
        # Belt and braces. Registration refuses these now, but a row stored before that
        # check existed must not become a navigation: the browser is sent here, and
        # javascript:/data: would execute in this origin with the session in reach.
        raise HTTPException(status_code=400, detail="redirect_uri scheme is not allowed")

    if not body.code_challenge:
        # PKCE is not optional here. Without a challenge the code is bearer-only, and a code
        # that leaks in a redirect chain is then enough on its own.
        raise HTTPException(status_code=400, detail="code_challenge is required (PKCE, S256)")

    code = "pac_" + secrets.token_urlsafe(32)
    db.add(OAuthCode(
        code_hash=hash_token(code),
        client_id=client.client_id,
        # The identity comes from the verified session, never from the request body.
        user_id=current.id,
        tenant_id=current.tenant_id,
        redirect_uri=body.redirect_uri,
        code_challenge=body.code_challenge,
        # Granted scope is fixed, not requested: the tool set is read-only, so there is
        # nothing else to grant and no negotiation to get wrong.
        scopes=READ_SCOPE,
        expires_at=_now() + CODE_TTL,
    ))
    db.commit()

    from urllib.parse import urlencode
    sep = "&" if "?" in body.redirect_uri else "?"
    params = {"code": code}
    if body.state:
        params["state"] = body.state
    return {"redirect_to": f"{body.redirect_uri}{sep}{urlencode(params)}"}
