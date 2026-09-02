# SIEM and S3 delivery

Palivane pushes findings to your SIEM and your data lake as they happen, and can archive
the complete capture record to your own S3 bucket. Four routes, which you can run in any
combination:

| Route | What it sends | Where it lands |
| --- | --- | --- |
| **SIEM HTTP push** | findings, severity-gated | Splunk HEC, Sentinel, Elastic, Sumo, Datadog, any CEF consumer |
| **S3 findings** | findings, severity-gated, one object each | Panther log source, Athena, Snowflake external stage |
| **S3 event archive** | *every* analyzed event, benign included | your data lake, hour-partitioned NDJSON |
| **JSONL pull** | findings, filtered, incremental | anything that would rather poll than be pushed to |

All four are Enterprise features. The first three are configured in **Settings**; the
fourth needs only an API key.

The push routes are deliberately fire-and-forget. A slow or unreachable collector must
never add latency to a prompt or drop a capture, so delivery runs off the request path and
failures are recorded rather than raised. That is a real tradeoff, and the section on
[delivery health](#knowing-it-is-actually-working) is how you keep it honest.

## SIEM HTTP push

One generic forwarder in three output shapes. The vendor specifics (endpoint URL, token,
index) are your configuration, not per-vendor code in Palivane, so anything that accepts
one of these shapes works without waiting for us to add it.

| Format | Body | Auth header |
| --- | --- | --- |
| `json` (default) | the finding object below | `Authorization: Bearer <token>` |
| `splunk_hec` | `{"event": {...}, "sourcetype": "palivane:finding", "source": "palivane"}` | `Authorization: Splunk <token>` |
| `cef` | one CEF:0 line, `text/plain` | `Authorization: Bearer <token>` |

**Settings → SIEM forwarding**: endpoint URL, token, minimum severity (default `high`),
and format. The token is write-only, so it is never read back after you save it. **Send
test event** posts a real event to your collector and reports what came back, which is the
fastest way to find a wrong index or an expired token.

Requests are SSRF-guarded and time out in 8 seconds.

### The finding object

```json
{
  "vendor": "Palivane", "product": "Palivane",
  "event": "finding", "severity": "high", "risk_score": 88,
  "categories": ["secret_leak", "data_exfiltration"],
  "top_signals": [{"title": "AWS access key", "evidence": "AKIA****************"}],
  "surface": "llm_io", "subject": "Q3 Forecast (FINAL).xlsx",
  "actor": "dana@acme.com", "finding_id": 4213, "org": "acme",
  "origin": {"...": "the source document the content came from, when matched"},
  "ts": 1788283066
}
```

`top_signals` carries the concrete cause with **redacted** evidence, so a correlation rule
can key on what actually matched without your SIEM becoming a second copy of the secret.
`origin` is content-origin lineage: when Palivane can match leaked content back to the
document it came from, this is that document, so a rule can pivot to the file and its
owner.

In CEF the same data maps to `cs1=surface`, `cs2=categories`, `cs3=org`, `cs4=match`,
`cn1=risk`, `suser=actor`, `externalId=finding_id`, with severity scaled to CEF's 0-10.

## S3 findings delivery

One JSON object per finding, severity-gated, at:

```
<your-prefix>/palivane/findings/YYYY/MM/DD/<epoch-ms>-<random>.json
```

Date-partitioned so a Panther S3 log source, an Athena table, or a Snowflake external
stage can read it without any transformation step.

One object per finding rather than a batch is deliberate. Palivane runs on short-lived
instances that scale to zero, and a buffered batch is data you lose on shutdown. Finding
volume is low enough that per-object writes are the right call; batching would be a cost
optimisation, not a correctness one.

### Two ways to authorise it

**A cross-account IAM role (preferred).** No credential of yours is stored anywhere in
Palivane. Open **Settings → S3 delivery** and use the role setup helper, which gives you
three things: the AWS principal for this deployment, a per-org **external ID**, and a
ready-to-paste trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "<this deployment's principal>"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:ExternalId": "plv-<your external id>"}}
  }]
}
```

The external ID is a confused-deputy guard, not a secret: it stops another Palivane tenant
naming your role. The role needs exactly one permission, `s3:PutObject` on the delivery
bucket. Nothing reads, lists, or deletes.

On the managed service the identity doing the assuming is itself federated from GCP with
no stored AWS secret, so there is no long-lived key on either side of the handoff.

**A static access key pair.** Always available, including on deployments with no AWS
identity of their own. Stored write-only. Use this if role assumption is not practical;
prefer the role if it is.

## S3 event archive

The audit-trail complement to findings delivery. Where the routes above send you the
**verdicts**, this archives **every analyzed event**, benign included, so your data lake
holds the complete capture record rather than only the parts that tripped a threshold.

```
<your-prefix>/palivane/events/YYYY/MM/DD/HH/<epoch-ms>-<random>.ndjson
```

Hour-partitioned NDJSON micro-batches, flushed on size or age (64 KB or 5 seconds by
default). Volume here is orders of magnitude higher than findings, which drives three
behaviours you should know about before you switch it on:

- **Prompt prose is redacted by default.** Signals and evidence are already redacted
  upstream. The prompt text itself ships redacted unless you explicitly opt into raw
  content, which is a separate switch from enabling the archive at all.
- **There is a daily byte budget per tenant**, 512 MB by default. Overflow is dropped. On
  the managed service these puts are internet egress from GCP to AWS, so this is a cost
  guard rather than a technical limit; ask if you need it raised.
- **A saturated dispatch pool drops the batch.** Capture never blocks on archival.

Unlike the findings sinks, archive failures are logged and counted rather than passed over
quietly. An archive that silently loses data defeats its own purpose.

One honest limit: the buffer is in memory, so an abrupt instance kill can lose up to one
flush window. A clean shutdown flushes synchronously.

## JSONL pull

If you would rather poll:

```
GET /api/export/findings?since=<ISO8601>&severity=high&surface=llm_io&limit=5000
```

Authenticate as a console admin or with an `ak_…` API key, so a scheduled SIEM poller can
run without a human session. The response is JSONL, oldest first, and carries an
`X-Palivane-Next-Since` header to use as the next poll's watermark.

The watermark is inclusive: a finding exactly on the boundary is re-sent rather than
skipped. Deduplicate on `(finding_id, last_seen)`. Losing an event is worse than seeing one
twice, so the filter errs toward re-sending.

## Knowing it is actually working

Fire-and-forget is the right design for the capture path and the wrong design for your
peace of mind, so every delivery attempt is recorded. **Settings** shows attempt and
failure counts and the last error for each sink, and the same data is available at
`GET /api/siem/status`. Delivery failures are also exported as Prometheus metrics.

A tenant whose HEC token expired should see that in the console, not discover a month of
silent data loss.

Two caveats on those numbers. They are per-instance and reset when a process restarts, so
treat them as an observability aid rather than a ledger: under horizontal scale each
instance reports only the deliveries it attempted. The last error is the part that matters,
and any instance seeing failures will show it.

## Choosing between them

- **A SIEM you already run**: HTTP push, minimum severity `high`. Add the JSONL pull if
  your SIEM prefers to poll or you need to backfill.
- **A data lake or Panther**: S3 findings delivery, with a cross-account role.
- **Compliance evidence, or you want the full record**: add the event archive. Budget for
  the volume and leave content redacted unless you have a specific reason not to.
- **Both a SIEM and a lake**: run them together. They are independent sinks and neither
  depends on the other.
