// Public "Use cases" page at /use-cases. Concrete scenarios Palivane addresses, mapped to
// the real capture planes and detectors. Reuses the landing (lp-*) design language.
import { SiteNav, SiteFooter, Shot } from "./SiteChrome.jsx";
import { IconTarget, IconShield, IconAlert, IconInbox, IconClipboard, IconPlug } from "./icons.jsx";

const CASES = [
  {
    icon: <IconTarget />, tag: "The obvious one",
    seg: "security", title: "Someone pastes customer data into ChatGPT",
    body: "It happens on a deadline, with good intentions. Palivane checks what people send to ChatGPT, Claude, Gemini, and Copilot and stops the customer records, passwords, and source code, then points them at a tool you've approved instead of just saying no.",
  },
  {
    icon: <IconShield />, tag: "Developers move fast",
    seg: "engineering", title: "Your engineers want Claude Code and Cursor",
    body: "Good, they're faster with them. Palivane lets the assistant read the code it's meant to work on, while still catching API keys and credentials hidden in it, flagging the settings that let it act without asking, and stopping destructive commands before they run.",
  },
  {
    icon: <IconInbox />, tag: "Your own AI overshares",
    seg: "compliance", title: "Your internal AI answers questions it shouldn't",
    body: "Copilot, Glean, or your own internal assistant will happily surface HR files, salary data, or a confidential deal to whoever asks. Palivane checks each answer against who's allowed to see what, and flags or blocks when restricted material reaches the wrong person.",
  },
  {
    icon: <IconAlert />, tag: "Assistants that act",
    seg: "engineering", title: "An AI assistant has real access to your systems",
    body: "Modern assistants don't just answer, they read files, run commands, and call other services. Palivane gives each one a boundary: which tools it may use, which commands it may run, which files it may open. Anything outside that gets stopped, not just logged.",
  },
  {
    icon: <IconClipboard />, tag: "Credentials already loose",
    seg: "security", title: "Keys are sitting on laptops and in your repos",
    body: "Prompts aren't the only way a secret escapes. Palivane finds credentials already sitting on developer machines (the first place info-stealing malware looks) and keeps new ones out of your repositories, with a one-time sweep of what's already committed.",
  },
  {
    icon: <IconAlert />, tag: "Agents nobody is watching",
    seg: "engineering", title: "An AI agent runs in CI with your deploy keys",
    body: "Handing a coding agent a GitHub Actions job is the new normal, and that job often holds cloud credentials no developer would paste into a chat window. Palivane reads your workflows before you merge them: which agents run there, what secrets reach them, whether approvals are switched off, and the trigger and permission mistakes that let a fork's pull request run in your CI at all.",
  },
  {
    icon: <IconInbox />, tag: "You ship AI yourself",
    seg: "engineering", title: "The AI feature in your product needs a guard",
    body: "Point your own app at Palivane and every prompt gets checked for the attacks aimed at AI: hijacking its instructions, talking it past its rules, or coaxing out its hidden setup and data. It checks the answers on the way back out, too.",
  },
  {
    icon: <IconPlug />, tag: "Someone asks for proof",
    seg: "compliance", title: "Your auditor or biggest customer asks what you do about AI",
    body: "Palivane shows which people and teams are actually covered and which aren't, keeps a full record of every decision it made, and produces a monthly summary you can hand to a board or a security questionnaire. Signed DPA available.",
  },
];

// The nav offers these three audiences, so the page has to actually answer to them.
// A flat wall of eight scenarios makes a visitor read all eight to find their own.
const SEGMENTS = [
  { id: "engineering", label: "Engineering",
    blurb: "Coding assistants and agents that read your files, run your commands, and hold real credentials." },
  { id: "security", label: "Security teams",
    blurb: "Finding the AI tools nobody registered, and the credentials already sitting where they shouldn't." },
  { id: "compliance", label: "Compliance",
    blurb: "Showing who is covered, what was decided, and where the evidence lives when somebody asks." },
];

export default function UseCases() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">USE CASES</div>
        <h1>Which of these is your problem?</h1>
        <p>Most companies arrive with one of these already on their mind. Palivane covers all of
           them from a single console, so solving the first one does not mean buying again for
           the next.</p>
      </section>

      {SEGMENTS.map((sg, i) => (
        <section key={sg.id} id={sg.id} className={`lp-section ${i % 2 ? "alt" : ""}`}>
          <div className="lp-wrap">
            <div className="lp-band-head">
              <span className="lp-eyebrow">{sg.label}</span>
              <p className="lp-sub" style={{ marginBottom: 0 }}>{sg.blurb}</p>
            </div>
            <div className="lp-cards lp-cards-2">
              {CASES.filter((c) => c.seg === sg.id).map((c) => (
                <div key={c.tag} className="lp-card">
                  <span className="lp-card-icon">{c.icon}</span>
                  <span className="tag tag-ai" style={{ marginLeft: 2 }}>{c.tag}</span>
                  <h3 style={{ marginTop: 10 }}>{c.title}</h3>
                  <p>{c.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>
      ))}

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Start by seeing what is actually happening</h2>
          <p className="lp-sub">Before you write a policy, get the list: every AI tool in use,
             approved or not, broken down by team, and what sensitive data each one actually
             received.</p>
          <Shot lead src="/shots/discovery.png?v=5" alt="Inventory of AI tools in use" />
        </div>
      </section>

      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-banner">
            <IconShield width={22} height={22} />
            <div>
              <strong>Try it on your own traffic.</strong> Connect one source and watch real findings
              land in minutes. Watch-only until you say otherwise.
            </div>
            <a className="primary-btn slim" href="/#signin" style={{ textDecoration: "none" }}>Open the console →</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
