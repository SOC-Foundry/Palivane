# Cloud marketplace listings

Why: marketplaces are how enterprise procurement buys (committed-spend burn-down makes us
effectively discounted vs invoice vendors), and competitors already sell there (Harmonic
and Knostic list on AWS Marketplace with public pricing). Listing is free on all three;
the marketplaces take ~3% of revenue **transacted through them** — a lead-gen or free
listing transacts nothing.

## The honest integration ladder

| Tier | Integration needed | What it gets |
|---|---|---|
| **Lead-gen / "Contact me"** | None | A findable listing that routes buyers to sales@ |
| **Free container listing** (self-hosted edition) | Push image to their registry + product form | Real installs, no billing plumbing |
| **Transactable SaaS** | Fulfillment APIs (AWS ResolveCustomer/Entitlements, GCP Procurement API, Azure SaaS Fulfillment v2) + metering | Committed-spend burn-down, private offers — the actual money path |

**Sequencing decision:** start at tiers 1–2 on all three now (free, this week), build the
transactable-SaaS integration once (AWS first — largest volume) when a real deal asks
for it. Do not build three billing integrations speculatively.

## Per-marketplace runbooks

| File | Marketplace | Entry tier |
|---|---|---|
| `aws.md` | AWS Marketplace | Free container listing (self-hosted) + seller registration for later SaaS |
| `gcp.md` | Google Cloud Marketplace | Free "deploy via Marketplace" listing (self-hosted) |
| `azure.md` | Azure Marketplace | **"Contact me"** listing — zero integration, fastest |

`listing-copy.md` holds the shared paste-ready copy (title, summaries at each length
limit, long description, categories, keywords, support links). `assets/` has the logo at
every size the three stores require (48/90/120/216/255/512, transparent, rendered from
the shipped SVG); screenshots reuse `extension/store-assets/` + the console shots in
`assets/` root of the repo.

## Account-bound steps (owner)

1. **AWS**: aws.amazon.com/marketplace/management — register as seller under the SOC
   Foundry AWS account (free; bank/tax only needed when a listing transacts).
2. **Azure**: partner.microsoft.com — join the Microsoft AI Cloud Partner Program (free)
   → enroll in "commercial marketplace".
3. **GCP**: console.cloud.google.com/producer-portal under the `palivane` org — Partner
   Advantage signup (free tier).

Each runbook says exactly what to click and what to paste from `listing-copy.md`.
