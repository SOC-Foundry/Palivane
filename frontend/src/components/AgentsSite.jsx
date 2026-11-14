// The agent story, demo first: what Palivane does when the thing sending the prompt is an
// agent that acts, not a person who reads. Every control named here is a shipped one; the
// wording follows the module docstrings (provenance.py, lanes.py, activity.py, containment.py,
// agent_graph.py) and the console's Agents page. The file is AgentsSite because Agents.jsx
// is the console tab.
import { demoUrl } from "../deployment.js";
import { Clip, SiteFooter, SiteNav } from "./SiteChrome.jsx";

const CONTROLS = [
  ["Identity, not a shared key",
   "Each agent is registered with its own credential or a workload OIDC identity, a least-privilege role, its own rate limit and its own block threshold. A tool call that cannot say which agent made it is marked unattested, and blocked when you turn enforcement on."],
  ["Checked before it runs",
   "Shell commands, file reads and tool calls are scored on the way in, including local stdio MCP: sensitive paths, destructive commands, tool poisoning, servers nobody approved. The agent waits for the verdict instead of the audit log catching up later."],
  ["Instruction provenance",
   "Agents are told what to do by tool results, fetched pages, files and other agents, which nobody typed. When that inbound content carries an injection, the agent is tainted for a window, and an action inside it that reaches a payoff gets one more signal: acting on an instruction nobody typed, naming the source."],
  ["Agent-to-agent flow graph",
   "Which agent fed which, drawn from the messages between them, with the hop where risk crossed marked. The question after an incident is where it came in, and the graph answers it."],
  ["Unattended agents",
   "Fleet names the agents running round the clock or for days on end with nobody at the keyboard, by hours seen rather than by a tag someone set, and lets you contain one from the same row."],
  ["Containment",
   "One action pauses an agent on every plane: prompts and tool calls denied, model calls refused. An agent that goes quiet instead of being stopped is flagged, with its usual hours taken into account so an evening is not an alarm."],
  ["Private lanes instead of blocks",
   "Regulated data in an agent's prompt can go to your zero-retention or self-hosted endpoint for that provider instead of being refused. The finding is still recorded, with the lane it took; injections and dangerous commands still block."],
  ["Agents in CI",
   "Workflows are read before merge: which agents run there, what secrets reach them, whether approvals are off, and the trigger and permission mistakes that let a fork's pull request run in your CI at all."],
];

const DEMO_STOPS = [
  ["Agents", "The registered agents, their roles and limits, the OIDC mapping, and a session token minted from a long-lived credential that never leaves the box."],
  ["Agents › Agent-to-agent flow", "The A2A graph the demo org's seeded messages produce, with the hop that carried an injected instruction."],
  ["Findings", "A coding agent about to run a dangerous command over MCP, and an agent in CI holding production credentials, each with the signals that scored it."],
  ["Fleet › Unattended", "Agents with no person behind them, and the Contain button beside each."],
];

export default function AgentsSite() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">AI AGENTS</div>
        <h1>Agents that act need a boundary <span className="lp-hl">that acts.</span></h1>
        <p className="lp-sub">Claude Code, Cursor, your own agents and the ones in CI read files, run
           commands and call each other. Palivane gives each one an identity, checks each action
           before it runs, tracks where its instructions came from, and can stop one everywhere
           in a single click. See it on the demo org before you install anything.</p>
        <div className="lp-cta">
          <a className="primary-btn" href={demoUrl()}>Open the demo org</a>
          <a className="lp-nav-ghost wide" href="#clip">Watch the clip</a>
        </div>
      </section>

      <section className="lp-section" id="clip">
        <div className="lp-wrap">
          <Clip src="/shots/agent-demo.mp4?v=2" poster="/shots/agent-demo-poster.png" lead
                caption="The analyst investigating a credential-leak finding and recommending an action, attestation allowing an OIDC agent while blocking an unattested one, and the agent-to-agent flow graph." />
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <span className="lp-eyebrow">What is different</span>
            <h2 className="lp-h2">Eight controls <span className="lp-hl">a prompt scanner does not have</span></h2>
          </div>
          <div className="lp-cards lp-cards-2">
            {CONTROLS.map(([h, p]) => (
              <div key={h} className="lp-card"><h3>{h}</h3><p>{p}</p></div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <span className="lp-eyebrow">Demo first</span>
            <h2 className="lp-h2">Four stops in the <span className="lp-hl">demo org</span></h2>
          </div>
          <p className="lp-sub" style={{ textAlign: "left", margin: "0 0 18px" }}>
            The demo org is a read-only console seeded with people, devices, agents and the
            findings they produced. No account is needed. Open it and go to:
          </p>
          <div className="lp-steps">
            {DEMO_STOPS.map(([h, p], i) => (
              <div key={h} className="lp-step">
                <span className="lp-step-n">{i + 1}</span>
                <div><h3>{h}</h3><p>{p}</p></div>
              </div>
            ))}
          </div>
          <div className="lp-cta" style={{ marginTop: 22, justifyContent: "flex-start" }}>
            <a className="primary-btn" href={demoUrl()}>Open the demo org</a>
            <a className="lp-nav-ghost wide" href="/assessment">Then run the 7-day assessment</a>
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-faq-wrap">
          <h2 className="lp-h2">Where the edges are</h2>
          <p className="lp-sub">The boundary is the hops the sensors see: the hook in the coding
             assistant, the proxy on the machine, the gateway your agents call through, and the
             CI workflow file. An agent on a machine with none of those installed is outside it,
             and Fleet says so rather than counting it as clean. Attestation enforcement is a
             switch you turn on once your agents carry identity; until then unattested calls are
             flagged, not refused. Provenance tracks a window after an injection arrives, not the
             agent's whole life.{" "}
            <a className="lp-textlink" href="/coverage">What each surface requires →</a></p>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
