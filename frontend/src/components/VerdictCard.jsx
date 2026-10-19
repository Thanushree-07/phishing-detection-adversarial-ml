const toneStyles = {
  PHISH: { border: "border-danger", text: "text-danger", dot: "bg-danger" },
  SAFE: { border: "border-safe", text: "text-safe", dot: "bg-safe" },
  unknown: { border: "border-border", text: "text-text-muted", dot: "bg-text-faint" },
};

export default function VerdictCard({ title, subtitle, label, probability, note }) {
  const tone = toneStyles[label] || toneStyles.unknown;

  return (
    <div className={`bg-panel border-l-2 ${tone.border} border-y border-r border-border rounded-sm px-5 py-4`}>
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="text-sm font-medium text-text-primary">{title}</div>
          {subtitle && <div className="text-xs text-text-faint font-mono">{subtitle}</div>}
        </div>
        <span className={`w-2 h-2 rounded-full ${tone.dot}`} />
      </div>

      <div className={`font-mono text-2xl font-semibold ${tone.text}`}>
        {label || "—"}
      </div>

      {probability !== undefined && probability !== null && (
        <div className="mt-2 text-xs text-text-muted font-mono">
          phishing probability: {(probability * 100).toFixed(1)}%
        </div>
      )}

      {note && <div className="mt-2 text-xs text-text-faint">{note}</div>}
    </div>
  );
}
