# SCIM 2.0 provisioning (Okta / Entra ID / OneLogin)

Let the IdP own the user lifecycle: joiners are created as analysts, leavers are
deactivated on the IdP's next sync (live sessions killed immediately). Roles stay a
console decision; deleting in the IdP deactivates rather than erases, so findings history
and the audit trail survive offboarding.

## Palivane side (once)

Settings → **User provisioning (SCIM 2.0)** → Generate token. Copy it now — only its
hash is stored. Base URL: `https://<your-app-host>/scim/v2`.

## Okta

Applications → your Palivane app → Provisioning → Integration: SCIM 2.0, Base URL as
above, **HTTP Header auth** with the token. Enable *Create Users*, *Update User
Attributes*, *Deactivate Users*. Okta probes with `userName eq` filters — supported;
anything fancier returns an honest 501 rather than wrong results.

## Entra ID

Enterprise application → Provisioning → Automatic; Tenant URL = the base URL, Secret
Token = the token. Entra sends path-less PATCH bodies — supported. Start provisioning.

## Notes

- Rotating the token (Generate again) invalidates the old one immediately — the IdP
  fails until it gets the new value; revoke stops provisioning outright.
- The **last active admin cannot be deactivated over SCIM** (409) — a mis-scoped push
  must not lock the org out of its own console.
- Provisioned users get an unusable random password: they sign in via SSO or the
  password-reset flow. SCIM never mints a credential.
