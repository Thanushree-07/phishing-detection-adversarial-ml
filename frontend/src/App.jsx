import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import NavRail from "./components/NavRail";
import Scan from "./pages/Scan";
import Evade from "./pages/Evade";
import Inject from "./pages/Inject";
import Results from "./pages/Results";
import { api } from "./api/client";

export default function App() {
  const [llmConfigured, setLlmConfigured] = useState(false);

  useEffect(() => {
    api
      .status()
      .then((s) => setLlmConfigured(s.llm_configured))
      .catch(() => {});
  }, []);

  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-ink">
        <NavRail llmConfigured={llmConfigured} />
        <main className="flex-1 px-10 py-10">
          <Routes>
            <Route path="/" element={<Scan />} />
            <Route path="/evade" element={<Evade />} />
            <Route path="/inject" element={<Inject />} />
            <Route path="/results" element={<Results />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
