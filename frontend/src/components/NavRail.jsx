import { NavLink } from "react-router-dom";
import { ScanLine, Zap, ShieldAlert, BarChart3, Fish } from "lucide-react";

const links = [
  { to: "/", label: "Scan", icon: ScanLine, end: true },
  { to: "/evade", label: "Evade", icon: Zap },
  { to: "/inject", label: "Inject", icon: ShieldAlert },
  { to: "/results", label: "Results", icon: BarChart3 },
];

export default function NavRail({ llmConfigured }) {
  return (
    <nav className="w-56 shrink-0 border-r border-border bg-panel flex flex-col h-screen sticky top-0">
      <div className="px-5 py-6 flex items-center gap-2.5 border-b border-border">
        <Fish size={22} className="text-amber" strokeWidth={2} />
        <div>
          <div className="text-sm font-semibold leading-tight">Phish/Detect</div>
          <div className="text-[11px] text-text-faint leading-tight font-mono">
            ml + adversarial
          </div>
        </div>
      </div>

      <div className="flex-1 py-4 px-3 flex flex-col gap-1">
        {links.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded text-sm transition-colors ${
                isActive
                  ? "bg-panel2 text-text-primary border-l-2 border-amber pl-[10px]"
                  : "text-text-muted hover:text-text-primary hover:bg-panel2/60"
              }`
            }
          >
            <Icon size={16} strokeWidth={2} />
            {label}
          </NavLink>
        ))}
      </div>

      <div className="px-5 py-4 border-t border-border">
        <div className="flex items-center gap-2 text-[11px] font-mono text-text-faint">
          <span
            className={`inline-block w-1.5 h-1.5 rounded-full ${
              llmConfigured ? "bg-safe" : "bg-amber"
            }`}
          />
          {llmConfigured ? "llm: groq live" : "llm: offline fallback"}
        </div>
      </div>
    </nav>
  );
}
