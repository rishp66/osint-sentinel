// Production deployments (frontend served from a different origin than the API)
// can set VITE_API_BASE_URL=https://api.sentinel.example.com at build time.
// In local dev this stays empty so requests go through the Vite proxy.
const API_BASE = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

function url(path) {
  return `${API_BASE}${path}`;
}

export async function runScan(target) {
  const resp = await fetch(url('/scan'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target }),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: 'Network error' }));
    throw new Error(err.detail || `HTTP ${resp.status}`);
  }
  return resp.json();
}

export async function checkHealth() {
  const resp = await fetch(url('/health'));
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: 'Network error' }));
    throw new Error(err.detail || `HTTP ${resp.status}`);
  }
  return resp.json();
}
