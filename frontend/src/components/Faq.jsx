// The buyer FAQ, shared by the landing page and /pricing. The landing shows the three a
// buyer asks first (where the text goes, what turning it on does, who touches laptops) and
// links to /pricing#faq, which carries the whole list. One list, so an answer cannot be
// corrected on one page and left stale on the other.
import { useState } from "react";
import { SELF_HOSTED } from "../deployment.js";

export const FAQ = [
  { q: "Where does our prompt text actually go?",
    a: SELF_HOSTED
      ? "To the Palivane backend you deploy, and nowhere beyond it, so no vendor holds your prompts. Scoring is deterministic (rules and heuristics, no AI service in the loop) unless you switch on the optional LLM judge, which sends the content it reviews to the model provider you choose."
      : "To Palivane, and nowhere beyond it. By default we keep the verdict and its metadata and discard the text itself: what we hold is that a prompt to ChatGPT carried an AWS key, not the prompt. Scoring is deterministic (rules and heuristics, no AI service in the loop) unless you switch on the optional LLM judge, which sends the content it reviews to a model provider (your own account if you supply a key, otherwise ours). Prefer that none of it reaches us? Self-hosting runs the same detection inside your own infrastructure, as a supported Enterprise deployment." },
  { q: "What happens the moment we turn it on?",
    a: "Nothing is blocked. Palivane starts in monitor mode and gives you an inventory of the AI tools in use and what has been going to them. Enforcement is a switch you flip later." },
  { q: "Does anyone have to touch every laptop?",
    a: "No. A browser extension and a small CLI do go on each machine, pushed by browser policy and your MDM (or one command a person runs once), so nothing needs a per-machine visit. The gateway and the SaaS connectors put nothing on a machine." },
  { q: "Will it break the AI tools people already pay for?",
    a: "No. The hooks score a prompt alongside the request instead of sitting in its path, so personal Claude and ChatGPT sign-ins keep working. Gateway routing is available, and optional." },
  { q: "What if the backend is unreachable?",
    a: "Capture fails open. A down collector never blocks a prompt or breaks a developer's tool. Confirmed secret and PII leaks are the exception and still hard-block." },
  { q: "How much of a team does this need to run?",
    a: "One person, part time. Set it up once, then work from digests rather than a queue." },
];

// How many of FAQ the landing page shows; /pricing#faq shows them all.
export const FAQ_FIRST = 3;

export function Faq({ items, className = "" }) {
  const [openQ, setOpenQ] = useState(0);
  return (
    <div className={`lp-faq ${className}`}>
      {items.map((f, i) => (
        <div key={f.q} className={`lp-faq-item ${openQ === i ? "is-open" : ""}`}>
          <button type="button" className="lp-faq-q" aria-expanded={openQ === i}
                  onClick={() => setOpenQ(openQ === i ? -1 : i)}>
            <span>{f.q}</span>
            <span className="lp-faq-sign" aria-hidden="true" />
          </button>
          {openQ === i && <p className="lp-faq-a">{f.a}</p>}
        </div>
      ))}
    </div>
  );
}
