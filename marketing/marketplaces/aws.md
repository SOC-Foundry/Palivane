# AWS Marketplace — free container listing (self-hosted edition) + seller reg

Two moves: register as seller now, list the **self-hosted edition** as a free container
product (no billing plumbing), leave transactable SaaS for when a deal asks.

1. aws.amazon.com/marketplace/management → **Register as seller** under the SOC Foundry
   AWS account (free; public listings of free products need no bank/tax).
2. Push the self-hosted image to a public/marketplace ECR repo:
   the repo's `docker-compose` backend image (`deploy/` docs) — retag and
   `aws ecr` push per the product-load instructions.
3. Products → Server → Create **container product** (delivery: ECR image; free pricing).
4. Paste listing copy; logo `assets/logo-120.png`; link `palivane.io/docs` for usage
   instructions (compose + Helm paths documented in deploy/).
5. Review is automated scans + human content review (days-to-weeks).

Transactable SaaS later: SaaS product type + ResolveCustomer/Entitlements integration in
the backend (billing.py sibling), then private offers unlock committed-spend deals.
