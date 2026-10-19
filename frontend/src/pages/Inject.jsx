import { useEffect, useState } from "react";
import { Loader2, ChevronDown, ChevronUp } from "lucide-react";
import { api } from "../api/client";

const DEFAULT_MESSAGE =
  "Dear Customer, we detected unusual activity on your account. Click the link below within 24 hours to verify your identity or your account will be permanently suspended. http://secure-verify-account1829.xyz/login";

function ClassifierResult({ title, result, baseIsPhish }) {
  const label = result?.label;
  const isError = typeof label === "string" && (label.startsWith("ERROR") || label === "UNPARSEABLE");
  let msg, cls;
  if (isError) {
    msg = label === "UNPARSEABLE" ? "model gave no clear answer" : "LLM call failed";
    cls = "text-amber";
  } else if (!baseIsPhish) {
    msg = "no attack to measure — the clean message was already judged SAFE";
    cls = "text-text-muted";
  } else if (result?.attack_succeeded) {
    msg = "attack succeeded — model said SAFE";
    cls = "text-danger";
  } else {
    msg = "attack failed — model still said PHISH";
    cls = "text-safe";
  }
  const color = isError ? "text-amber" : label === "SAFE" && baseIsPhish ? "text-danger" : label === "SAFE" ? "text-safe" : "text-safe";
  return (
    <div className="border border-border rounded-sm px-5 py-4 bg-panel">
      <div className="text-sm font-medium mb-3">{title}</div>
      <div className={`font-mono text-xl font-semibold ${color}`}>{label ?? "—"}</div>
      <div className="mt-2 text-xs">
        <span className={cls}>{msg}</span>
      </div>
      {isError && label?.startsWith("ERROR") && (
        <div className="mt-2 text-[11px] font-mono text-text-faint break-all">{label}</div>
      )}
    </div>
  );
}

function InjectionExplainer({ result }) {
  const ex = result.explanation || {};
  const base = result.base_message || "";
  return (
    <div className="border border-amber/30 rounded-sm bg-panel overflow-hidden">
      <div className="px-5 py-3 border-b border-border text-xs font-mono text-amber">
        what was injected — {result.attack_label}
      </div>

      <div className="px-5 py-4 space-y-4">
        {ex.how && <p className="text-sm text-text-muted">{ex.how}</p>}

        <div>
          <div className="text-xs font-mono text-text-faint mb-1.5">
            the attacker's hidden instruction
          </div>
          <div className="font-mono text-sm text-danger">"{result.hidden_instruction}"</div>
        </div>

        <div>
          <div className="text-xs font-mono text-text-faint mb-1.5">
            exact text added to the message (invisible characters shown as markers)
          </div>
          <pre className="bg-panel2 border border-border rounded-sm px-4 py-3 text-xs font-mono whitespace-pre-wrap break-all text-amber">
            {result.injected_part_visible}
          </pre>
        </div>

        <div>
          <div className="text-xs font-mono text-text-faint mb-1.5">
            full payload the LLM received
          </div>
          <pre className="bg-panel2 border border-border rounded-sm px-4 py-3 text-xs font-mono whitespace-pre-wrap break-all text-text-muted">
            <span>{base}</span>
            {"\n\n"}
            <mark className="bg-amber/25 text-amber rounded-sm">{result.injected_part_visible}</mark>
          </pre>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div className="border border-border rounded-sm px-4 py-3">
            <div className="font-mono text-text-faint mb-1">a human reader sees</div>
            <div className="text-text-muted">{ex.human_sees}</div>
          </div>
          <div className="border border-border rounded-sm px-4 py-3">
            <div className="font-mono text-text-faint mb-1">the LLM sees</div>
            <div className="text-text-muted">{ex.llm_sees}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function DefenseExplainer({ result }) {
  const ex = result.explanation || {};
  return (
    <div className="border border-border rounded-sm bg-panel px-5 py-4 space-y-3">
      <div className="text-xs font-mono text-text-faint">how the defense responds</div>
      {ex.defense && <p className="text-sm text-text-muted">{ex.defense}</p>}
      {result.sanitizer_changed_payload ? (
        <div>
          <div className="text-xs font-mono text-text-faint mb-1.5">
            text after sanitization (injection removed or neutralised)
          </div>
          <pre className="bg-panel2 border border-border rounded-sm px-4 py-3 text-xs font-mono whitespace-pre-wrap break-all text-safe">
            {result.sanitized_payload}
          </pre>
        </div>
      ) : (
        <div className="text-xs text-text-muted">
          The sanitizer found nothing to strip here (the instruction is plain text), so protection relies on the
          hardened prompt that tells the model to treat the message as data.
        </div>
      )}
    </div>
  );
}

export default function Inject() {
  const [attacks, setAttacks] = useState([]);
  const [attack, setAttack] = useState("");
  const [message, setMessage] = useState(DEFAULT_MESSAGE);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [showPayload, setShowPayload] = useState(false);

  useEffect(() => {
    api
      .injectAttacks()
      .then((list) => {
        setAttacks(list);
        if (list.length) setAttack(list[0].id);
      })
      .catch(() => setError("Could not reach the backend."));
  }, []);

  async function handleRun(e) {
    e.preventDefault();
    if (!message.trim() || !attack) return;
    setLoading(true);
    setError(null);
    setShowPayload(false);
    try {
      const data = await api.inject(message.trim(), attack);
      setResult(data);
    } catch {
      setError("Could not reach the backend.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-4xl">
      <h1 className="text-2xl font-semibold mb-1">Prompt injection demo</h1>
      <p className="text-text-muted text-sm mb-8 max-w-xl">
        Hide an instruction inside a phishing message and see whether it can
        trick the LLM classifier into saying SAFE — undefended vs. defended.
      </p>

      <form onSubmit={handleRun} className="mb-8 space-y-4">
        <div>
          <label className="block text-xs font-mono text-text-faint mb-1.5">
            base phishing message
          </label>
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            rows={4}
            className="w-full bg-panel border border-border rounded-sm px-3 py-2.5 font-mono text-sm outline-none focus:border-amber/60 transition-colors resize-none"
          />
        </div>

        <div className="flex items-end gap-3">
          <div className="flex-1">
            <label className="block text-xs font-mono text-text-faint mb-1.5">
              injection technique
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
            Run injection
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
          {!result.base_is_phish && (
            <div className="text-xs border border-amber/30 bg-amber/5 text-amber rounded-sm px-4 py-2.5">
              Without any injection, the classifier rated your message {result.clean_label}, so it is not
              treated as phishing. A prompt injection can only be measured against a message that is normally
              caught as PHISH — try a phishing message instead.
            </div>
          )}

          <InjectionExplainer result={result} />

          <button
            onClick={() => setShowPayload((s) => !s)}
            className="flex items-center gap-1.5 text-xs font-mono text-text-faint hover:text-text-muted transition-colors"
          >
            {showPayload ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            {showPayload ? "hide" : "show"} actual payload sent
          </button>

          {showPayload && (
            <pre className="border border-border rounded-sm bg-panel2 px-4 py-3 text-xs font-mono text-text-muted whitespace-pre-wrap break-all">
              {result.payload_visible ?? result.payload}
            </pre>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <ClassifierResult title="Undefended classifier" result={result.undefended} baseIsPhish={result.base_is_phish} />
            <ClassifierResult title="Defended classifier" result={result.defended} baseIsPhish={result.base_is_phish} />
          </div>

          <DefenseExplainer result={result} />

          {result.llm_offline_mode && (
            <div className="text-xs font-mono text-amber border border-amber/30 bg-amber/5 rounded-sm px-4 py-2.5">
              running in offline fallback mode — add GROQ_API_KEY to .env for real LLM results
            </div>
          )}
        </div>
      )}
    </div>
  );
}
