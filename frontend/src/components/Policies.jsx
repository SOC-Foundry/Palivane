// Policies — enable/disable each detection check per tenant, grouped by area, with presets.
// Toggling writes tenant.disabled_checks (PATCH /api/tenant); the engine drops signals for
// disabled checks on the next scan. Changes apply immediately.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

// Preset -> the set of checks it DISABLES. "Strict" = everything on. "Balanced" mirrors the
// common default. "Monitor" keeps every check recording (blocking is governed by mode, not
// by turning checks off), so it also disables nothing — presets are a quick reset to "all on"
// plus room to grow per-preset later.
const PRESET_DISABLED = { strict: [], balanced: [], monitor: [] };

export default function Policies({ tenant, onTenant }) {
  const [cat, setCat] = useState(null);
  const [saving, setSaving] = useState("");
  const [err, setErr] = useState(null);
  const [flash, setFlash] = useState(null);

  const load = useCallback(async () => {
    try { setCat(await api.policies()); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const disabledSet = () => new Set((cat?.checks || []).filter((c) => !c.enabled).map((c) => c.key));

  async function persist(nextDisabled, label) {
    setErr(null); setSaving(label || "…");
    try {
      const t = await api.updateTenant({ disabled_checks: [...nextDisabled] });
      onTenant?.(t);
      await load();
      setFlash("Saved — applies to new scans immediately.");
      setTimeout(() => setFlash(null), 2500);
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setSaving(""); }
  }

  function toggle(key) {
    const d = disabledSet();
    d.has(key) ? d.delete(key) : d.add(key);
    persist(d, key);
  }
  function applyPreset(name) {
    persist(new Set(PRESET_DISABLED[name] || []), `preset:${name}`);
  }

  if (!cat) return <div className="connect"><p className="muted">Loading policies…</p></div>;

  const total = cat.checks.length;
  const on = cat.checks.filter((c) => c.enabled).length;

  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Policies</h1>
          <p className="page-sub">Choose which detection checks run for your organization.
             <strong> {on} of {total}</strong> enabled — changes apply immediately to new scans.</p>
        </div>
        <div className="head-actions">
          {["strict", "balanced", "monitor"].map((p) => (
            <button key={p} className="ghost-btn" disabled={!!saving}
                    onClick={() => applyPreset(p)} style={{ textTransform: "capitalize" }}>
              {p}
            </button>
          ))}
        </div>
      </div>

      {err && <div className="error">{err}</div>}
      {flash && <div className="hint" style={{ color: "var(--benign)" }}>{flash}</div>}

      {cat.groups.map((group) => (
        <div key={group} className="panel settings-card">
          <h2>{group}</h2>
          <div className="policy-list">
            {cat.checks.filter((c) => c.group === group).map((c) => (
              <div className="policy-row" key={c.key}>
                <div className="policy-text">
                  <div className="policy-name">
                    {c.label}
                    <span className={`policy-state ${c.enabled ? "on" : "off"}`}>
                      {c.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </div>
                  <div className="policy-desc">{c.desc}</div>
                </div>
                <button
                  role="switch" aria-checked={c.enabled} aria-label={`Toggle ${c.label}`}
                  className={`toggle ${c.enabled ? "toggle-on" : ""}`}
                  disabled={saving === c.key}
                  onClick={() => toggle(c.key)}>
                  <span className="toggle-knob" />
                </button>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
