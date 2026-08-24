# 10. Acceptable Use & Endpoint Security

**Owner:** Founder · **Effective:** 2026-07-19 · **Review:** annual

## Endpoint requirements (any device touching production or the repo)

- Full-disk encryption, OS auto-updates, screen lock ≤ 5 minutes.
- MFA on every account in the access inventory (Policy 02); a password manager for
  unique credentials.
- No production Restricted data on endpoints (Policy 07), operator work uses IDs and
  metadata; secrets are read from Secret Manager at point of use, never saved locally.
- **Dogfooding as posture evidence:** the operator's own development runs Palivane's
  local planes (hooks, posture reporter, VS Code sensor), so IDE extensions, MCP
  configs, and AI-tool usage on the endpoint are continuously reported to the palivane
  org, our endpoint monitoring story is the product itself.

## Acceptable use

Company systems and data are used only for operating the business. Prohibited:
disabling security controls (branch protection, MFA, encryption), sharing credentials,
storing customer data outside approved systems, using production data in development.

## AI tool use (we practice the policy we sell)

AI coding assistants are permitted **through Palivane's own governance**: gateway-routed
or hook-covered, with findings reviewed in the palivane org. Pasting Restricted data
(customer content, keys) into ungoverned AI tools is prohibited, exactly the behavior
Palivane exists to catch.

## Future personnel

These requirements apply from day one of any hire, verified during onboarding and
attested annually alongside security-awareness training.
