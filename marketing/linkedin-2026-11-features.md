# LinkedIn posts: the November features

One post per feature, in the order to publish them (strongest first). Each stands alone,
no hashtags beyond three, no emoji, and ends on the one thing a reader can do. Pair each
with the matching screenshot from the console (Fleet, Connect, Agents, Settings, a finding).

---

## 1. Undo for agents

Every product in this space can stop an AI agent. We added the button that puts the files back.

Palivane's hook journals every file before a coding agent changes it. Contain the agent and
you get a second button: Undo files. The device restores every file the agent touched since
the containment began and removes the ones it created, then reports what it did. From a
terminal it is one command: palivane-hook undo --since 30m.

Stopping an agent at 14:07 does not help with the twenty files it rewrote between 13:40 and
14:07. Now it does.

Try it on the demo org at palivane.io/agents.

---

## 2. Canary instructions: a susceptibility score per agent

Which of your agents follow orders they find in documents? We measured it instead of guessing.

Paste one line into a wiki page, a README or a shared doc. Any agent that reads it is
recorded. Any agent that then runs the command the line names has obeyed an instruction
nobody typed, and the finding names the document it came from. Fleet turns the result into a
number per agent, trending month on month.

It is the prompt-injection question every vendor hand-waves, answered with your own agents on
your own documents.

palivane.io/agents

---

## 3. Your record: the view for the person being watched

Security tools watch employees and show the result to the security team. We added the other
direction.

Every person in a Palivane org can open Your record and see what was captured in their AI
use, what was stopped and what was only noted, whether their text or only metadata is stored
and for how long, which sensors report from their machines, whether they are contained right
now, and what regulated data of theirs reached a provider. One click exports it: a
data-subject access request answered by the person themselves.

Monitoring that the monitored can see is monitoring a works council can agree to.

palivane.io/assessment

---

## 4. Commit attestations

"Which code was AI-written, and was it reviewed?" Your auditor will ask. Your git log can
answer.

With palivane-hook git-install, every commit made after a coding agent worked in a repo
carries two trailers: Palivane-AI-Assisted: yes, and Palivane-Scan with the agent, the tool
calls, the files, what was blocked and the time window. The commit is registered with the
findings Palivane raised in that window, signed, and checkable by sha.

Transparency for AI-assisted code in the one form engineers already accept.

palivane.io/agents

---

## 5. Phantom dependencies

Models invent package names. People register them. Developers paste the install line.

Palivane now checks every install line a model suggests, and every one a coding agent is about
to run, against PyPI, npm, crates.io, RubyGems and the Go module proxy. A package that does not
exist, or appeared this week, is flagged before the paste, and the agent's install is stopped
before it runs.

Slopsquatting, caught at the only moment that matters.

palivane.io/proof

---

## 6. Blast radius

"A key leaked" is not a severity. "This key can read every S3 bucket" is.

Palivane's secrets ledger already showed where a leaked credential travelled. It now says what
it unlocks: a classic GitHub token reaches every repo the user can, a fine-grained one only what
it was scoped to, a Slack user token acts as the person, a live Stripe key moves money. For an
AWS key, the IAM user's policies are read through the role you already gave us, so rotation
gets a priority order.

The value itself is never stored. The assessment is made while it is in memory, once.

palivane.io/how-it-works

---

## 7. Shared threat signatures

One organisation's confirmed poisoned MCP tool now protects every other within minutes.

When an analyst confirms a tool-poisoning finding and the org has opted in, the digest of that
tool description goes to a shared feed: a hash, a masked excerpt, a count. Nothing names the
reporter. Every Palivane org checks every advertised tool against the feed, and a hit scores as
a confirmed poisoning, whatever the pattern match says. A false positive withdraws the report.

Vendors blog about what they caught in the wild. This is the feed that makes it a product, built
from the reviews customers already do.

palivane.io/proof
