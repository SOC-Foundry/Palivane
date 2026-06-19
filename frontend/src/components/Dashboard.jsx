export default function Dashboard({ stats }) {
  if (!stats) return null;
  const cards = [
    { label: "Total analyzed", value: stats.total, tone: "neutral" },
    { label: "Open", value: stats.open, tone: "neutral" },
    { label: "High / critical", value: stats.high_risk, tone: "danger" },
    { label: "AI-weaponized", value: stats.ai_weaponized, tone: "warn" },
  ];
  return (
    <div className="dashboard">
      {cards.map((c) => (
        <div key={c.label} className={`stat-card stat-${c.tone}`}>
          <div className="stat-value">{c.value}</div>
          <div className="stat-label">{c.label}</div>
        </div>
      ))}
    </div>
  );
}
