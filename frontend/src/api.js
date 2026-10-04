const API = import.meta.env.VITE_API || "http://localhost:8000";
export async function api(path, opts) {
  let r;
  try { r = await fetch(API + path, opts); } catch { throw new Error("Backend unreachable. Start it with: uvicorn main:app --port 8000"); }
  if (!r.ok) { let m = `Request failed (${r.status})`; try { m = (await r.json()).detail || m; } catch {} throw new Error(m); }
  return r.json();
}
export const json = (method, body) => ({ method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
