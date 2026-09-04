# Vendor register (subservice organizations & critical vendors)

Reviewed at least annually; last review 2026-09. "Data tier": what of ours/our customers'
data the vendor can touch.

| Vendor | Purpose | Data tier | Their attestation | Review |
|---|---|---|---|---|
| Google Cloud (Cloud Run, Cloud SQL, Secret Manager) | Production hosting | All customer data (encrypted) | SOC 2 / ISO 27001 (public) | 2026-09 |
| Cloudflare | Edge/TLS, DNS, Worker front door | Traffic in transit | SOC 2 / ISO 27001 (public) | 2026-09 |
| GitHub | Source, CI, deploy identity (WIF) | Source code, CI secrets refs | SOC 2 (public) | 2026-09 |
| Google Workspace | Email, docs, identity | Corporate email/docs | SOC 2 / ISO (public) | 2026-09 |
| Stripe | Billing | Billing PII (cardholder data stays with Stripe) | PCI-DSS L1, SOC 2 | 2026-09 |
| Anthropic / OpenAI / Google AI | LLM judge (optional, off by default per tenant) | Content of judged prompts when judge enabled | SOC 2 (public) | 2026-09 |

Adding a vendor = a row here + a look at their attestation BEFORE production data flows.
