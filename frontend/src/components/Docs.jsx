// Public documentation at /docs — renders the repo's own markdown (single source of
// truth: the files under docs/ ship with the code they describe; vite inlines them at
// build time via ?raw). Curated list only — internal runbooks stay out.
import { useEffect, useMemo } from "react";
import { marked } from "marked";
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";

import overviewMd from "../../../docs/overview.md?raw";
import setupMd from "../../../docs/setup.md?raw";
import claudeMd from "../../../docs/claude-deployment.md?raw";
import mdmMd from "../../../docs/mdm-policy-pack.md?raw";
import tokensMd from "../../../docs/tokens-and-identity.md?raw";
import atRestMd from "../../../docs/at-rest-scanning.md?raw";
import dataFlowsMd from "../../../docs/data-flows.md?raw";
import pilotMd from "../../../docs/pilot-smoke-test.md?raw";

const DOCS = [
  { slug: "overview", title: "Overview & architecture", md: overviewMd },
  { slug: "setup", title: "Setting up Palivane", md: setupMd },
  { slug: "claude", title: "Deploying for Claude", md: claudeMd },
  { slug: "mdm-policy-pack", title: "MDM policy pack", md: mdmMd },
  { slug: "tokens-and-identity", title: "Tokens & identity", md: tokensMd },
  { slug: "at-rest-scanning", title: "S3 & repo scanning", md: atRestMd },
  { slug: "data-flows", title: "Data flows: what leaves the machine", md: dataFlowsMd },
  { slug: "pilot", title: "Pilot smoke test", md: pilotMd },
];

marked.setOptions({ gfm: true, breaks: false });

// Stable heading ids so section links work (marked doesn't add ids by default).
const renderer = new marked.Renderer();
renderer.heading = ({ text, depth }) => {
  const id = String(text).toLowerCase().replace(/<[^>]+>/g, "")
    .replace(/[^a-z0-9\s-]/g, "").trim().replace(/\s+/g, "-");
  return `<h${depth} id="${id}">${text}</h${depth}>`;
};

export default function Docs({ slug }) {
  const doc = DOCS.find((d) => d.slug === slug) || DOCS[0];
  const html = useMemo(() => marked.parse(doc.md, { renderer }), [doc]);

  useEffect(() => {
    document.title = `${doc.title} — Palivane docs`;
    if (window.location.hash) {
      document.getElementById(window.location.hash.slice(1))?.scrollIntoView();
    } else {
      window.scrollTo(0, 0);
    }
  }, [doc]);

  return (
    <div className="landing">
      <SiteNav />
      <div className="docs-layout">
        <aside className="docs-side">
          <div className="lp-tagline" style={{ marginBottom: 10 }}>DOCUMENTATION</div>
          <nav>
            {DOCS.map((d) => (
              <a key={d.slug} href={`/docs/${d.slug}`}
                 className={d.slug === doc.slug ? "active" : ""}>{d.title}</a>
            ))}
          </nav>
          <p className="muted" style={{ fontSize: 12, marginTop: 18 }}>
            These pages render straight from the repository — they ship with the code
            they describe. Questions: <a href="mailto:support@tachtech.net">support@tachtech.net</a>
          </p>
        </aside>
        <main className="docs-prose" dangerouslySetInnerHTML={{ __html: html }} />
      </div>
      <SiteFooter />
    </div>
  );
}
