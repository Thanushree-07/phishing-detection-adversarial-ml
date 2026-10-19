# Running the full app (backend + React frontend)

This is a two-part app: a Python backend (FastAPI) that serves your trained
models, and a React frontend that talks to it. Both need to be running at
the same time, in two separate terminals.

## 1. Backend (Terminal 1)

From the project root:

```bash
pip install -r backend/requirements.txt
uvicorn backend.main:app --reload --port 8000
```

You should see `Uvicorn running on http://127.0.0.1:8000`. Leave this
terminal open.

Visit http://localhost:8000/docs to see the raw API if you want to check
it directly.

### Before running the backend

Make sure these already exist (produced by scripts elsewhere in the repo):

- `models/baseline_logreg.pkl`, `models/baseline_gbt.pkl`
  → from `models/train_baseline.py`
- `text_model/saved_model/tfidf_phishing_model.joblib` (and the hardened /
  adversarially trained versions, for the full Results page)
  → from `text_model/tfidf_phishing_model.py` and
    `text_model/adversarial_training.py`

If any are missing, the backend still starts — those specific predictions
will just come back empty, and the frontend shows "model not found" instead
of crashing.

### LLM classifier (Groq)

Add your key to `.env` in the project root:

```
GROQ_API_KEY=your_key_here
```

No key yet? The app still works — the LLM tab runs a simple offline
fallback instead, clearly labeled as such everywhere it appears. Add the
key later and restart the backend; no code changes needed.

## 2. Frontend (Terminal 2)

From the project root:

```bash
cd frontend
npm install
npm run dev
```

Open the URL it prints (usually http://localhost:5173).

## What you'll see

- **Scan** — paste a URL, get predictions from all three models side by
  side, plus the full feature breakdown
- **Evade** — run a character-level evasion attack on a phishing URL,
  compare before/after predictions
- **Inject** — run a prompt injection attack against the LLM classifier,
  compare undefended vs. defended
- **Results** — the team's actual generated charts and tables (robustness
  comparison, confusion matrices, injection before/after), pulled live from
  `text_model/results/` and `attacks/*.csv`

## Building for a real deployment (optional)

```bash
cd frontend
npm run build
```

This produces a static `dist/` folder. Not required for local
demoing/grading — `npm run dev` is enough.
