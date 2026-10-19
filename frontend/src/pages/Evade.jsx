import { useEffect, useState } from "react";
import { ArrowRight, Loader2 } from "lucide-react";
import { api } from "../api/client";

function outcome(before, after) {
  const b = before?.label, a = after?.label;
  if (!b || !a) return { text: "model not loaded", cls: "text-text-faint" };
  if (b === "PHISH" && a === "SAFE") return { text: "evasion succeeded — phishing URL now slips through", cls: "text-danger" };
  if (b === "PHISH" && a === "PHISH") return { text: "evasion failed — still caught", cls: "text-safe" };
  if (b === "SAFE" && a === "PHISH") return { text: "false alarm — the attack made a legitimate URL look malicious", cls: "text-amber" };
  return { text: "no change — URL was already classified SAFE, so there is nothing to evade", cls: "text-text-muted" };
}

function Prob({ r }) {
  return r?.phishing_probability != null ? (
    <span className="text-text-faint text-xs ml-1">({(r.phishing_probability * 100).toFixed(0)}%)</span>
  ) : null;
}

function ResultRow({ label, before, after }) {
  const o = outcome(before, after);
  return (
    <div className="border border-border rounded-sm px-5 py-4 bg-panel">
      <div className="text-sm font-medium mb-3">{label}</div>
      <div className="flex items-center gap-4 font-mono text-sm">
        <span className={before?.label === "PHISH" ? "text-danger" : "text-safe"}>
          {before?.label ?? "—"}<Prob r={before} />
        </span>
        <ArrowRight size={14} className="text-text-faint shrink-0" />
        <span className={after?.label === "PHISH" ? "text-danger" : "text-safe"}>
          {after?.label ?? "—"}<Prob r={after} />
        </span>
      </div>
      <div className="mt-3 text-xs">
        <span className={o.cls}>{o.text}</span>
      </div>
    </div>
  );
}

function Highlighted({ segments, fallback, tone }) {
  if (!segments?.length) return <>{fallback}</>;
  return (
    <>
      {segments.map((seg, i) =>
        seg.changed ? (
          <mark
            key={i}
            className={`rounded-sm px-[1px] ${
              tone === "orig"
                ? "bg-danger/25 text-text"
                : "bg-amber/30 text-amber underline decoration-amber decoration-2 underline-offset-2"
            }`}
          >
            {seg.text}
          </mark>
        ) : (
          <span key={i}>{seg.text}</span>
        )
      )}
    </>
  );
}

function XRay({ segments }) {
  if (!segments?.length) return null;
  return (
    <span>
      {segments.map((seg, i) =>
        seg.changed ? (
          <span key={i}>
            {Array.from(seg.text).map((ch, j) => (
              <span
                key={j}
                className="inline-block align-middle mx-[1px] px-1 rounded-sm bg-amber/20 text-amber text-[10px] leading-5 border border-amber/40"
                title={ch}
              >
                U+{ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}
              </span>
            ))}
          </span>
        ) : (
          <span key={i}>{seg.text}</span>
        )
      )}
    </span>
  );
}

function ChangesTable({ changes }) {
  if (!changes?.length) return null;
  return (
    <div className="border border-border rounded-sm bg-panel overflow-x-auto">
      <div className="px-5 py-3 text-xs font-mono text-text-faint border-b border-border">
        {changes.length} character{changes.length === 1 ? "" : "s"} changed
      </div>
      <table className="w-full text-sm font-mono">
        <thead>
          <tr className="text-left text-xs text-text-faint">
            <th className="px-5 py-2 font-normal">pos</th>
            <th className="px-3 py-2 font-normal">original</th>
            <th className="px-3 py-2 font-normal">replaced with</th>
            <th className="px-3 py-2 font-normal">codepoint</th>
            <th className="px-3 py-2 font-normal">unicode name</th>
          </tr>
        </thead>
        <tbody>
          {changes.map((c, i) => (
            <tr key={i} className="border-t border-border/60">
              <td className="px-5 py-1.5 text-text-faint">{c.index}</td>
              <td className="px-3 py-1.5">{c.original}</td>
              <td className="px-3 py-1.5 text-amber">{c.replacement || "(removed)"}</td>
              <td className="px-3 py-1.5 text-text-muted">{c.codepoint}</td>
              <td className="px-3 py-1.5 text-text-faint text-xs">{c.unicode_name}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Evade() {
  const [attacks, setAttacks] = useState([]);
  const [attack, setAttack] = useState("");
  const [url, setUrl] = useState("http://secure-login-verify-account1829.xyz/confirm");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [xray, setXray] = useState(true);

  useEffect(() => {
    api
      .evadeAttacks()
      .then((list) => {
        setAttacks(list);
        if (list.length) setAttack(list[0].id);
      })
      .catch(() => setError("Could not reach the backend."));
  }, []);

  async function handleRun(e) {
    e.preventDefault();
    if (!url.trim() || !attack) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.evade(url.trim(), attack);
      setResult(data);
    } catch {
      setError("Could not reach the backend.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-4xl">
      <h1 className="text-2xl font-semibold mb-1">Evasion attack demo</h1>
      <p className="text-text-muted text-sm mb-8 max-w-xl">
        Apply a small character-level perturbation to a phishing URL and see
        whether the baseline and TF-IDF models still catch it.
      </p>

      <form onSubmit={handleRun} className="mb-8 space-y-4">
        <div>
          <label className="block text-xs font-mono text-text-faint mb-1.5">
            phishing url
          </label>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="w-full bg-panel border border-border rounded-sm px-3 py-2.5 font-mono text-sm outline-none focus:border-amber/60 transition-colors"
          />
        </div>

        <div className="flex items-end gap-3">
          <div className="flex-1">
            <label className="block text-xs font-mono text-text-faint mb-1.5">
              attack type
            </label>
            <select
              value={attack}
              onChange={(e) => setAttack(e.target.value)}
              className="w-full bg-panel border border-border rounded-sm px-3 py-2.5 text-sm outline-none focus:border-amber/60 transition-colors"
            >
              {attacks.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.label}
                </option>
              ))}
            </select>
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-2.5 bg-amber text-ink font-medium text-sm rounded-sm hover:bg-amber/90 transition-colors disabled:opacity-60 flex items-center gap-2"
          >
            {loading && <Loader2 size={14} className="animate-spin" />}
            Run attack
          </button>
        </div>
      </form>

      {error && (
        <div className="border border-danger/40 bg-danger/5 text-danger text-sm rounded-sm px-4 py-3 mb-8 font-mono">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-6">
          <div className="border border-border rounded-sm px-5 py-4 bg-panel2 space-y-2">
            <div className="text-xs font-mono text-text-faint">
              original <span className="text-text-faint/70">(characters that will change are marked)</span>
            </div>
            <div className="font-mono text-sm break-all">
              <Highlighted segments={result.diff?.original_segments} fallback={result.original_url} tone="orig" />
            </div>
            <div className="text-xs font-mono text-text-faint pt-2">
              attacked <span className="text-text-faint/70">(substituted characters highlighted)</span>
            </div>
            <div className="font-mono text-sm break-all text-amber/90">
              <Highlighted segments={result.diff?.attacked_segments} fallback={result.attacked_url} tone="att" />
            </div>
            <div className="pt-3 border-t border-border/60 mt-3">
              <div className="flex items-center justify-between mb-1.5">
                <div className="text-xs font-mono text-text-faint">
                  x-ray view — what the computer actually sees
                </div>
                <button
                  type="button"
                  onClick={() => setXray((x) => !x)}
                  className="text-xs font-mono text-text-faint hover:text-text-muted"
                >
                  {xray ? "hide" : "show"}
                </button>
              </div>
              {xray && (
                <div className="font-mono text-sm break-all leading-7">
                  <XRay segments={result.diff?.attacked_segments} />
                </div>
              )}
              <div className="text-xs text-text-muted mt-2">
                {result.diff?.changes?.some((c) => c.replacement && c.replacement.codePointAt(0) > 127)
                  ? "Each U+xxxx chip is a letter that looks like a normal English letter but is a different character (e.g. Cyrillic). A normal letter like \"s\" is U+0073; these are not."
                  : "Each U+xxxx chip is a character that was swapped in (e.g. a digit in place of a letter). The URL differs from the original, but these are ordinary ASCII characters, so it is not a Unicode look-alike."}
              </div>
            </div>
            {result.unchanged && (
              <div className="text-xs text-text-muted pt-2">
                This attack had nothing to change in this URL — try a URL with more letters, e.g. containing a, e, o.
              </div>
            )}
          </div>

          {result.punycode_host && (
            <div className="border border-border rounded-sm px-5 py-4 bg-panel space-y-1">
              <div className="text-xs font-mono text-text-faint">what DNS / the browser really sees (punycode, only for non-ASCII hostnames)</div>
              <div className="font-mono text-sm break-all text-amber">{result.punycode_host}</div>
              <div className="text-xs text-text-muted">
                The two URLs look the same on screen but are different strings — the Cyrillic letters make this
                a different domain and change what the models see.
              </div>
            </div>
          )}

          <ChangesTable changes={result.diff?.changes} />

          {result.baseline_before?.label === "SAFE" && result.tfidf_before?.label === "SAFE" && (
            <div className="text-xs border border-amber/30 bg-amber/5 text-amber rounded-sm px-4 py-2.5">
              Both models already rate the original URL as SAFE, so it is a legitimate-looking URL. Evasion
              only means something for a phishing URL; on a legitimate URL the interesting question is whether
              the attack triggers a false alarm.
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <ResultRow
              label="Baseline model (GBT)"
              before={result.baseline_before}
              after={result.baseline_after}
            />
            <ResultRow
              label="TF-IDF model"
              before={result.tfidf_before}
              after={result.tfidf_after}
            />
          </div>
        </div>
      )}
    </div>
  );
}
