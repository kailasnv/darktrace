// Backend client for the DarkTrace frontend.
//
//  - Main backend  (FastAPI, port 8000): /api/v1/alerts, /api/v1/dashboard/summary ...
//  - Login service (FastAPI, port 8001): /api/v1/auth/login | signup | refresh
//
// In dev, vite.config.js proxies  /api -> :8000  and  /login-api -> :8001,
// so no CORS setup is needed. For production set the VITE_* variables (see .env.example).

const API_URL = import.meta.env.VITE_API_URL ?? '';
const AUTH_URL = import.meta.env.VITE_AUTH_URL ?? '/login-api';
// 'main'          -> sign in / register through the main backend (/auth/token, /auth/register)
// 'login-service' -> sign in / sign up through the standalone login service (port 8001)
const AUTH_MODE = import.meta.env.VITE_AUTH_MODE || 'main';

const ACCESS_KEY = 'dt-access-token';
const REFRESH_KEY = 'dt-refresh-token';

const store = {
  get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } },
  del: (k) => { try { localStorage.removeItem(k); } catch { /* storage unavailable */ } },
};

export const getToken = () => store.get(ACCESS_KEY);
export const isLoggedIn = () => !!getToken();

export function clearSession() {
  store.del(ACCESS_KEY);
  store.del(REFRESH_KEY);
}

function saveTokens(data) {
  if (data.access_token) store.set(ACCESS_KEY, data.access_token);
  if (data.refresh_token) store.set(REFRESH_KEY, data.refresh_token);
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

// FastAPI errors: {detail: "text"} or {detail: [{msg, loc, ...}]} for validation errors
async function errorFrom(res) {
  let msg = `Request failed (${res.status})`;
  try {
    const body = await res.json();
    if (typeof body.detail === 'string') msg = body.detail;
    else if (Array.isArray(body.detail)) msg = body.detail.map((d) => d.msg).join('; ');
  } catch { /* non-JSON body */ }
  return new ApiError(msg, res.status);
}

// ---- auth ----------------------------------------------------------------

export async function login(username, password) {
  let res;
  if (AUTH_MODE === 'login-service') {
    res = await fetch(`${AUTH_URL}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
  } else {
    // OAuth2PasswordRequestForm expects form-encoded data, not JSON
    res = await fetch(`${API_URL}/api/v1/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username, password }),
    });
  }
  if (!res.ok) throw await errorFrom(res);
  saveTokens(await res.json());
}

export async function signup({ username, email, password }) {
  const url = AUTH_MODE === 'login-service'
    ? `${AUTH_URL}/api/v1/auth/signup`
    : `${API_URL}/api/v1/auth/register`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password }),
  });
  if (!res.ok) throw await errorFrom(res);
  return res.json();
}

export function logout() {
  clearSession();
  window.dispatchEvent(new Event('dt-auth-changed'));
}

// Only the login service issues refresh tokens
async function tryRefresh() {
  const refresh_token = store.get(REFRESH_KEY);
  if (AUTH_MODE !== 'login-service' || !refresh_token) return false;
  try {
    const res = await fetch(`${AUTH_URL}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token }),
    });
    if (!res.ok) return false;
    saveTokens(await res.json());
    return true;
  } catch {
    return false;
  }
}

// ---- authenticated requests ------------------------------------------------

export async function apiFetch(path, options = {}, retried = false) {
  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: { ...(options.headers || {}), Authorization: `Bearer ${getToken() || ''}` },
  });

  if (res.status === 401) {
    if (!retried && (await tryRefresh())) return apiFetch(path, options, true);
    logout(); // token missing/expired -> send the user back to the login screen
    throw new ApiError('Session expired — please sign in again', 401);
  }
  if (!res.ok) throw await errorFrom(res);
  return res.json();
}

export const getAlerts = () => apiFetch('/api/v1/alerts');
export const reviewAlert = (alertId, { status = 'Reviewed', note } = {}) =>
  apiFetch(`/api/v1/alerts/${encodeURIComponent(alertId)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, note }),
  });
export const getSummary = () => apiFetch('/api/v1/dashboard/summary');
export const getMe = () => apiFetch('/api/v1/auth/me');

// Sources + crawl jobs (Module 1 registry). Writes need role sysadmin/supervisor (sources)
// or sysadmin/supervisor/investigator/analyst (crawl jobs); the backend answers 403 otherwise.
export const getSources = () => apiFetch('/api/v1/sources?status_filter=active');
export const getCrawlJobs = (state) => apiFetch(`/api/v1/crawl-jobs${state ? `?state=${encodeURIComponent(state)}` : ''}`);
export const createCrawlJob = ({ intent_id, source_id, kind = 'manual' }) =>
  apiFetch('/api/v1/crawl-jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ intent_id, source_id, kind }),
  });

// ---- mapping backend alerts -> Threat Intelligence cards --------------------

const cap = (s) => (s ? String(s).charAt(0).toUpperCase() + String(s).slice(1).toLowerCase() : s);

function timeAgo(iso) {
  const mins = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  if (Number.isNaN(mins)) return '—';
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  if (mins < 1440) return `${Math.round(mins / 60)} hrs ago`;
  return `${Math.round(mins / 1440)} days ago`;
}

// AlertOut guarantees id / severity / title / created_at; the other fields are
// read defensively in case your schema has them under a different name.
export function alertToThreat(a) {
  // created_at is a naive UTC timestamp from the backend -> mark it as UTC
  const created = a.created_at && !/[zZ]|[+-]\d\d:?\d\d$/.test(a.created_at) ? `${a.created_at}Z` : a.created_at;
  return {
    id: a.id,
    name: a.title ?? 'Untitled alert',
    severity: cap(a.severity) || 'Low',
    ioc: a.ioc ?? a.indicator ?? a.ioc_value ?? '—',
    type: a.type ?? a.alert_type ?? a.category ?? 'Alert',
    source: a.source ?? 'Alerting',
    detected: timeAgo(created),
    detectedAt: created,
    status: cap(a.status) || 'Active',
    description: a.description ?? a.message ?? a.details ?? a.title ?? '',
  };
}
