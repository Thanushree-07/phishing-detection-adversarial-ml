const BASE_URL = "http://localhost:8000";

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`Request failed: ${res.status}`);
  }
  return res.json();
}

export const api = {
  status: () => request("/api/status"),

  scan: (url) =>
    request("/api/scan", {
      method: "POST",
      body: JSON.stringify({ url }),
    }),

  evadeAttacks: () => request("/api/evade/attacks"),

  evade: (url, attack) =>
    request("/api/evade", {
      method: "POST",
      body: JSON.stringify({ url, attack }),
    }),

  injectAttacks: () => request("/api/inject/attacks"),

  inject: (message, attack) =>
    request("/api/inject", {
      method: "POST",
      body: JSON.stringify({ message, attack }),
    }),

  results: () => request("/api/results"),
};

export const STATIC_BASE_URL = BASE_URL;
