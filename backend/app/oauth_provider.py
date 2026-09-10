"""OAuth 2.1 authorization server for the remote MCP endpoint — storage and token mechanics.

Palivane is its own authorization server because it is its own identity provider: users,
roles and tenants live here, and there is no external IdP every tenant shares. The MCP SDK
supplies the protocol — PKCE verification, code exchange, metadata documents, dynamic client
registration — and this supplies persistence plus the one thing no SDK can supply, which is
the decision about WHOSE data a token may read.

NOT WIRED YET. No routes reference this. Stage one is the token mechanics, so they can be
read and argued with before a browser can reach any of it; the consent step and the routes
are stage two.

The consent binding is `subject`. Every code and every token carries the id of the user who
approved it, and the MCP tools act as exactly that user — same as a console-scoped API key.
A token therefore cannot outrank the person who granted it, and `require_admin` still
applies to admin-gated tools.

Deliberate choices, each because the alternative is a known way to lose:

  Credentials are hashed at rest (hash_token, as api_keys already does). A database read
  must not yield a working credential.

  redirect_uri is matched EXACTLY against the registered list. No prefix, no wildcard, no
  "startswith" — a loose redirect check is the classic route by which an authorization code
  is delivered to somebody else.

  PKCE is required and S256 only. The spec permits `plain`, which defeats the purpose.

  Codes live ~60 seconds and are single use; a second exchange fails. A code is a handoff,
  not a credential, and one that can be replayed can be lifted from a log or a Referer.

  Refresh tokens rotate: exchanging one revokes it and issues a replacement, so a stolen
  refresh token stops working the moment the legitimate holder uses theirs.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .config import settings
from .models import OAuthClient, OAuthCode, OAuthToken as OAuthTokenRow
from .security import hash_token

# A code is a handoff between two hops of one browser redirect; it needs seconds, not
# minutes. Access tokens are short so a leaked one expires on its own; refresh carries the
# long-lived grant and rotates on every use.
CODE_TTL = timedelta(seconds=60)
ACCESS_TTL = timedelta(hours=1)
REFRESH_TTL = timedelta(days=30)

# One scope, matching the tool set: the remote MCP server exposes reads only. When a write
# tool is added it needs its own scope AND a decision about the allowlist, not a quiet
# widening of this one.
READ_SCOPE = "palivane:read"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _consent_url() -> str:
    base = (settings.public_base_url or "https://app.palivane.io").rstrip("/")
    return f"{base}/app/oauth/consent"


class PalivaneOAuthProvider(OAuthAuthorizationServerProvider):
    """Persistence for the SDK's OAuth routes. One session factory, injected."""

    def __init__(self, session_factory):
        # Injected rather than importing SessionLocal: this runs outside dependency
        # injection, and binding to the module engine reads a different database than the
        # request is being served from wherever an override is in play.
        self._session = session_factory

    # --- clients ------------------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        db, close = self._session()
        try:
            row = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).one_or_none()
            if row is None:
                return None
            return OAuthClientInformationFull(
                client_id=row.client_id,
                client_name=row.client_name or None,
                redirect_uris=[u for u in (row.redirect_uris or "").split("\n") if u],
                scope=row.scope or READ_SCOPE,
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method="none",     # public client; PKCE is the proof
            )
        finally:
            close()

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Dynamic Client Registration. Registering is NOT an access grant.

        Open registration is what lets an MCP client connect without an admin provisioning
        it by hand, and it grants nothing: it records that some software exists and where it
        may be redirected. Reading anything still requires a real user to approve it, and
        the resulting token carries that user's identity and no more.
        """
        uris = [str(u) for u in (client_info.redirect_uris or [])]
        if not uris:
            raise ValueError("at least one redirect_uri is required")
        db, close = self._session()
        try:
            db.add(OAuthClient(
                client_id=str(client_info.client_id),
                client_name=(client_info.client_name or "")[:200],
                redirect_uris="\n".join(uris),
                # Never widen at registration: a client gets the read scope regardless of
                # what it asks for, so a request for something broader cannot mint it.
                scope=READ_SCOPE,
            ))
            db.commit()
        finally:
            close()

    # --- authorization ------------------------------------------------------------------

    async def authorize(self, client: OAuthClientInformationFull,
                        params: AuthorizationParams) -> str:
        """Hand the browser to the console's consent screen.

        The console keeps its session in localStorage, not a cookie, so this endpoint sees
        no identity: a browser arriving here is anonymous whatever the user is signed into.
        The SPA is the only place that holds the JWT, so it owns the consent step and posts
        the approval back with it.

        Every parameter here is re-validated when consent is submitted — client, exact
        redirect_uri, challenge — because they cross the browser in a URL and must be
        treated as untrusted on the way back.
        """
        from urllib.parse import urlencode
        q = urlencode({
            "client_id": client.client_id,
            "client_name": client.client_name or client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "state": params.state or "",
            "code_challenge": params.code_challenge or "",
            "scope": READ_SCOPE,
        })
        return f"{_consent_url()}?{q}"

    async def load_authorization_code(self, client: OAuthClientInformationFull,
                                      authorization_code: str) -> AuthorizationCode | None:
        db, close = self._session()
        try:
            row = (db.query(OAuthCode)
                     .filter(OAuthCode.code_hash == hash_token(authorization_code))
                     .one_or_none())
            # Belongs to another client, already spent, or expired: all three are "no such
            # code", answered identically so a caller learns nothing from which it was.
            if row is None or row.client_id != client.client_id:
                return None
            if row.used_at is not None or (row.expires_at and row.expires_at < _now()):
                return None
            return AuthorizationCode(
                code=authorization_code,
                scopes=(row.scopes or READ_SCOPE).split(),
                expires_at=row.expires_at.replace(tzinfo=timezone.utc).timestamp(),
                client_id=row.client_id,
                code_challenge=row.code_challenge or "",
                redirect_uri=row.redirect_uri,
                redirect_uri_provided_explicitly=True,
                subject=str(row.user_id) if row.user_id else None,
            )
        finally:
            close()

    async def exchange_authorization_code(self, client: OAuthClientInformationFull,
                                          authorization_code: AuthorizationCode) -> OAuthToken:
        """Spend the code once and issue the pair. PKCE was verified by the SDK."""
        db, close = self._session()
        try:
            row = (db.query(OAuthCode)
                     .filter(OAuthCode.code_hash == hash_token(authorization_code.code))
                     .one_or_none())
            if row is None or row.used_at is not None:
                raise ValueError("authorization code already used")
            row.used_at = _now()               # single use, before anything is issued
            access, refresh = self._issue_pair(db, row.client_id, row.user_id,
                                               row.tenant_id, row.scopes or READ_SCOPE)
            db.commit()
            return OAuthToken(access_token=access, token_type="Bearer",
                              expires_in=int(ACCESS_TTL.total_seconds()),
                              refresh_token=refresh, scope=row.scopes or READ_SCOPE)
        finally:
            close()

    # --- tokens -------------------------------------------------------------------------

    def _issue_pair(self, db, client_id: str, user_id, tenant_id, scopes: str):
        access = "pat_" + secrets.token_urlsafe(32)
        refresh = "prt_" + secrets.token_urlsafe(32)
        now = _now()
        db.add(OAuthTokenRow(token_hash=hash_token(access), kind="access", client_id=client_id,
                             user_id=user_id, tenant_id=tenant_id, scopes=scopes,
                             expires_at=now + ACCESS_TTL))
        db.add(OAuthTokenRow(token_hash=hash_token(refresh), kind="refresh", client_id=client_id,
                             user_id=user_id, tenant_id=tenant_id, scopes=scopes,
                             expires_at=now + REFRESH_TTL))
        return access, refresh

    def _load(self, db, token: str, kind: str):
        row = (db.query(OAuthTokenRow)
                 .filter(OAuthTokenRow.token_hash == hash_token(token),
                         OAuthTokenRow.kind == kind)
                 .one_or_none())
        if row is None or row.revoked_at is not None:
            return None
        if row.expires_at and row.expires_at < _now():
            return None
        return row

    async def load_access_token(self, token: str) -> AccessToken | None:
        db, close = self._session()
        try:
            row = self._load(db, token, "access")
            if row is None:
                return None
            return AccessToken(token=token, client_id=row.client_id,
                               scopes=(row.scopes or READ_SCOPE).split(),
                               expires_at=int(row.expires_at.replace(tzinfo=timezone.utc).timestamp()),
                               subject=str(row.user_id) if row.user_id else None)
        finally:
            close()

    async def load_refresh_token(self, client: OAuthClientInformationFull,
                                 refresh_token: str) -> RefreshToken | None:
        db, close = self._session()
        try:
            row = self._load(db, refresh_token, "refresh")
            if row is None or row.client_id != client.client_id:
                return None
            return RefreshToken(token=refresh_token, client_id=row.client_id,
                                scopes=(row.scopes or READ_SCOPE).split(),
                                expires_at=int(row.expires_at.replace(tzinfo=timezone.utc).timestamp()))
        finally:
            close()

    async def exchange_refresh_token(self, client: OAuthClientInformationFull,
                                     refresh_token: RefreshToken,
                                     scopes: list[str]) -> OAuthToken:
        """Rotate: the presented refresh token dies and a new pair is issued.

        Rotation is what makes a stolen refresh token survivable — the moment either party
        uses theirs, the other's stops working, so the theft surfaces instead of persisting
        silently for thirty days.
        """
        db, close = self._session()
        try:
            row = self._load(db, refresh_token.token, "refresh")
            if row is None or row.client_id != client.client_id:
                raise ValueError("invalid refresh token")
            # Never widen on refresh: a token cannot acquire scopes it was not granted.
            granted = row.scopes or READ_SCOPE
            row.revoked_at = _now()
            access, refresh = self._issue_pair(db, row.client_id, row.user_id,
                                               row.tenant_id, granted)
            db.commit()
            return OAuthToken(access_token=access, token_type="Bearer",
                              expires_in=int(ACCESS_TTL.total_seconds()),
                              refresh_token=refresh, scope=granted)
        finally:
            close()

    async def revoke_token(self, token) -> None:
        db, close = self._session()
        try:
            row = (db.query(OAuthTokenRow)
                     .filter(OAuthTokenRow.token_hash == hash_token(token.token))
                     .one_or_none())
            if row is not None and row.revoked_at is None:
                row.revoked_at = _now()
                db.commit()
        finally:
            close()
