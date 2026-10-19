import { useState } from "react";
import { Search, Loader2 } from "lucide-react";
import { api } from "../api/client";
import VerdictCard from "../components/VerdictCard";

export default function Scan() {
  const [url, setUrl] = useState("http://paypa1-secure-login.com/verify?acc=4471829");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function handleScan(e) {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.scan(url.trim());
      setResult(data);
    } catch (err) {
      setError(
        "Could not reach the backend. Make sure it's running: uvicorn backend.main:app --reload --port 8000"
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-4xl">
      <h1 className="text-2xl font-semibold mb-1">Scan a URL</h1>
      <p className="text-text-muted text-sm mb-8 max-w-xl">
        Checked against three independent classifiers at once — a feature-based
        baseline, a TF-IDF text model, and an LLM making a zero-shot judgment.
      </p>

      <form onSubmit={handleScan} className="mb-10">
        <div className="flex items-stretch gap-0 border border-border rounded-sm overflow-hidden bg-panel focus-within:border-amber/60 transition-colors">
          <div className="flex items-center pl-4 text-text-faint">
            <Search size={16} />
          </div>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="http://example.com/login"
            className="flex-1 bg-transparent px-3 py-3 font-mono text-sm outline-none placeholder:text-text-faint"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-6 bg-amber text-ink font-medium text-sm hover:bg-amber/90 transition-colors disabled:opacity-60 flex items-center gap-2"
          >
            {loading && <Loader2 size={14} className="animate-spin" />}
            {loading ? "Scanning" : "Scan"}
          </button>
        </div>
      </form>

      {error && (
        <div className="border border-danger/40 bg-danger/5 text-danger text-sm rounded-sm px-4 py-3 mb-8 font-mono">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-8">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <VerdictCard
              title="Baseline (GBT)"
              subtitle="hand-built features"
              label={result.baseline?.label}
              probability={result.baseline?.phishing_probability}
              note={!result.baseline && "model not found on disk"}
            />
            <VerdictCard
              title="TF-IDF model"
              subtitle="raw URL text"
              label={result.tfidf?.label}
              probability={result.tfidf?.phishing_probability}
              note={!result.tfidf && "model not found on disk"}
            />
            <VerdictCard
              title="LLM classifier"
              subtitle="zero-shot"
              label={result.llm?.label}
              note={
                result.llm_offline_mode
                  ? "offline fallback — add GROQ_API_KEY to .env"
                  : undefined
              }
            />
          </div>

          <div>
            <h2 className="text-sm font-medium text-text-primary mb-3">
              Feature breakdown <span className="text-text-faint font-mono text-xs">(used by the baseline model)</span>
            </h2>
            <div className="border border-border rounded-sm overflow-hidden">
              <table className="w-full text-sm font-mono">
                <tbody>
                  {Object.entries(result.features || {}).map(([key, val], i) => (
                    <tr
                      key={key}
                      className={i % 2 === 0 ? "bg-panel" : "bg-panel2"}
                    >
                      <td className="px-4 py-2 text-text-muted w-1/2">{key}</td>
                      <td className="px-4 py-2 text-text-primary">
                        {typeof val === "number" ? val.toFixed(4).replace(/\.?0+$/, "") : String(val)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
