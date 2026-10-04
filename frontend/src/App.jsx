import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import NetworkBackground from "./components/background/NetworkBackground";
import Sidebar from "./components/layout/Sidebar";
import Topbar from "./components/layout/Topbar";
import StatCard from "./components/dashboard/StatCard";
import Timeline from "./components/dashboard/Timeline";
import EvidenceGraph from "./components/dashboard/EvidenceGraph";
import { I } from "./components/icons";
import { useTheme } from "./context/ThemeContext";
import { api, json } from "./api";

const tabs = [["Overview", "cases"], ["Evidence", "evidence"], ["Timeline", "timeline"], ["Indicators", "indicators"], ["Memory", "memory"], ["Graph", "graph"], ["Reports", "evidence"]];
const cap = s => s.charAt(0) + s.slice(1).toLowerCase();
const kb = n => (n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB");
const IND_TABS = [["IP", "IP Addresses"], ["DOMAIN", "Domains"], ["SHA256", "File Hashes"], ["URL", "URLs"]];
const indMeta = i => i.previous_cases.length ? ["purple", "Historical match"] : i.external ? ["yellow", "External"] : i.type === "IP" ? ["green", "Internal"] : ["blue", "Observed"];

function MatchList({ mem }) {
  if (!mem.length) return <p className="muted pad">No historical matches found.</p>;
  return mem.map(m => (
      <div className="ir match" key={m.type + m.indicator}>
        <i className="pt purple" /><span>{m.indicator}<small>{m.type}</small></span>
        <span className="tag purple">{m.relationship.replace("_", " ")}</span><em>{m.previous_cases.map(p => p.case_number).join(", ")}</em>
      </div>
  ));
}

export default function App() {
  const [cases, setCases] = useState([]); const [cid, setCid] = useState(null);
  const [d, setD] = useState(null), [tl, setTl] = useState([]), [inds, setInds] = useState([]), [mem, setMem] = useState([]), [graph, setGraph] = useState(null), [ai, setAi] = useState(null);
  const [tab, setTab] = useState("Overview"), [navSel, setNavSel] = useState("Dashboard"), [q, setQ] = useState(""), [indTab, setIndTab] = useState("IP");
  const [busy, setBusy] = useState(""), [msg, setMsg] = useState(null), [form, setForm] = useState(null), [notif, setNotif] = useState(false);
  const fileRef = useRef();
  const { dark } = useTheme();
  const note = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 6000); };

  const load = useCallback(async id => {
    try {
      const [s, t, i, m, g] = await Promise.all([api(`/cases/${id}`), api(`/cases/${id}/timeline`), api(`/cases/${id}/indicators`), api(`/memory/matches?case_id=${id}`), api(`/cases/${id}/graph`)]);
      setCid(id); setD(s); setTl(t); setInds(i); setMem(m); setGraph(g); setAi(null);
    } catch (e) { note("err", e.message); }
  }, []);
  const refresh = useCallback(async pick => {
    try { const list = await api("/cases"); setCases(list); const id = pick ?? list[0]?.id; if (id) await load(id); } catch (e) { note("err", e.message); }
  }, [load]);
  useEffect(() => { refresh(); }, [refresh]);

  const act = async (label, fn) => { setBusy(label); try { await fn(); } catch (e) { note("err", e.message); } setBusy(""); };
  const createCase = e => { e.preventDefault(); act("create", async () => { const c = await api("/cases", json("POST", form)); setForm(null); await refresh(c.id); note("ok", `${c.case_number} created. Upload evidence next.`); }); };
  const upload = files => act("upload", async () => {
    for (const f of files) { const fd = new FormData(); fd.append("file", f); await api(`/cases/${cid}/evidence`, { method: "POST", body: fd }); }
    await load(cid); note("ok", `${files.length} file(s) uploaded. Click Analyze Evidence.`);
  });
  const analyze = () => act("analyze", async () => {
    const r = await api(`/cases/${cid}/analyze`, { method: "POST" }); await load(cid);
    if (r.errors.length) note("err", r.errors.join(" | "));
    else if (!r.indicators) note("err", "No indicators detected.");
    else note("ok", r.historical_matches ? `Historical match: ${r.historical_matches} indicator(s) seen in previous cases.` : `Extracted ${r.events} events and ${r.indicators} indicators. No historical matches found.`);
  });
  const demo = () => act("demo", async () => { const r = await api("/demo/seed", { method: "POST" }); await refresh(r.case_ids[r.case_ids.length - 1]); note("ok", "Demo loaded: CASE-002 shares indicators with CASE-001."); });
  const explain = () => act("ai", async () => setAi(await api("/ai/explain", json("POST", { case_id: cid }))));
  const go = (label, t) => { setNavSel(label); setTab(t); };

  const needle = q.trim().toLowerCase();
  const fInds = useMemo(() => inds.filter(i => !needle || `${i.type} ${i.value}`.toLowerCase().includes(needle)), [inds, needle]);
  const fTl = useMemo(() => tl.filter(e => !needle || `${e.event_type} ${e.description} ${e.src_ip} ${e.domain}`.toLowerCase().includes(needle)), [tl, needle]);
  const IndRow = i => { const [c, l] = indMeta(i); return <div className="ir" key={i.id}><i className={`pt ${c}`} /><span>{i.value}</span><span className={`tag ${c}`}>{l}</span><em>{i.previous_cases.join(", ")}</em></div>; };
  const risk = d ? d.risk_score : 0;
  const fmt = t => (t ? t.replace("T", " ").slice(0, 16) + " UTC" : "—");

  return (
      <div className={`app ${dark ? "dark" : "light"}`}>
        <NetworkBackground />
        <Sidebar navSel={navSel} onNav={go} onSettings={() => note("ok", "Settings are not part of the MVP.")} />

        <main>
          <Topbar q={q} setQ={setQ} hasAlert={mem.length > 0} onBell={() => setNotif(!notif)} />
          {notif && <div className="toast pop">{mem.length ? `${mem.length} historical match(es) in ${d?.case_number}` : "No new notifications"}</div>}
          {msg && <div className={`toast ${msg.type}`}>{msg.text}</div>}

          <div className="page">
            <div className="toolbar">
              <select value={cid || ""} onChange={e => load(+e.target.value)} disabled={!cases.length}>
                {!cases.length && <option>No cases yet</option>}
                {cases.map(c => <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>)}
              </select>
              <button className="primary ghost" onClick={() => setForm(form ? null : { title: "", description: "" })}>+ New Case</button>
              <button className="primary ghost" onClick={demo} disabled={!!busy}>{busy === "demo" ? "Loading…" : "Load Demo Data"}</button>
              {d && <button className="primary" onClick={analyze} disabled={!!busy || !d.evidence_count}>{busy === "analyze" ? "Analyzing…" : "Analyze Evidence"}</button>}
            </div>
            {form && (
                <form className="card newcase" onSubmit={createCase}>
                  <input autoFocus required placeholder="Case title" value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} />
                  <input placeholder="Description (optional)" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
                  <button className="primary">Create case</button>
                </form>
            )}

            {!d ? (
                <div className="card empty"><h4>No case selected</h4><p>Create a case, or load the demo dataset (CASE-001 + CASE-002) to see forensic memory in action.</p></div>
            ) : (<>
              <section className="head">
                <div>
                  <div className="title-row"><h2>{d.case_number}</h2><span className="open">{d.status}</span></div>
                  <h3>{d.title}</h3><p>{d.description || "No description."}</p>
                </div>
                <div className="head-right"><div className="meta">
                  <div><small>Created</small>{fmt(d.created_at)}</div><div><small>Last Updated</small>{fmt(d.updated_at)}</div>
                  <div><small>Investigator</small>Kunal Dubey</div><div><small>Priority</small><span className="yellow">{cap(d.priority)}</span></div>
                </div></div>
              </section>

              {mem.length > 0 && (
                  <div className="alert" onClick={() => setTab("Memory")}>
                    <I n="memory" /><div><b>Historical match detected</b><span>{mem.map(m => `${m.indicator} previously observed in ${m.previous_cases.map(p => p.case_number).join(", ")}`).join(" · ")}</span></div>
                  </div>
              )}

              <section className="stats">
                {[["Evidence Files", d.evidence_count, "Uploaded to this case", "evidence", "blue"], ["Events", d.event_count, "Parsed from evidence", "graph", "blue"],
                  ["Indicators", d.indicator_count, "IPs, domains, hashes, URLs", "indicators", "green"], ["Historical Matches", d.historical_matches, "Found in other cases", "link", "red"],
                  ["Risk Level", cap(d.risk_level), "", "shield", "yellow"]].map(([l, v, s, ic, c]) => (
                    <StatCard key={l} label={l} value={v} sub={s} icon={ic} tone={c} risk={risk} reasons={d.risk_reasons} />
                ))}
              </section>

              <div className="tabs">{tabs.map(([t, ic]) => <button key={t} className={tab === t ? "on" : ""} onClick={() => { setTab(t); setNavSel(t === "Overview" ? "Dashboard" : t); }}><I n={ic} />{t}{t === "Memory" && mem.length > 0 ? ` (${mem.length})` : ""}</button>)}</div>

              <input ref={fileRef} type="file" multiple hidden onChange={e => { if (e.target.files.length) upload([...e.target.files]); e.target.value = ""; }} />
              {(() => {
                const EvTable = () => (
                    <table><thead><tr><th>File Name</th><th>Type</th><th>Size</th><th>SHA-256</th><th>Status</th></tr></thead>
                      <tbody>{d.evidence.length ? d.evidence.map(f => <tr key={f.id}><td>{f.filename}</td><td><span className="tag blue">{f.type}</span></td><td>{kb(f.size)}</td><td className="mono">{f.sha256.slice(0, 12)}…</td><td className={f.analysis_status === "Analyzed" ? "green" : f.analysis_status === "Failed" ? "red" : ""}>{f.analysis_status}</td></tr>) : <tr><td colSpan="5" className="muted">No evidence uploaded yet.</td></tr>}</tbody></table>
                );
                const Up = <button className="primary ghost" onClick={() => fileRef.current.click()} disabled={!!busy}><I n="upload" />{busy === "upload" ? "Uploading…" : "Upload Evidence"}</button>;
                if (tab === "Overview") return (<>
                  <section className="row2">
                    <div className="card"><div className="ch"><h4><I n="timeline" />Investigation Timeline</h4><a onClick={() => setTab("Timeline")}>View All →</a></div>
                      <Timeline events={fTl.slice(0, 6)} empty="No events yet. Upload evidence and click Analyze Evidence." /></div>
                    <div className="card"><div className="ch"><h4><I n="graph" />Evidence Graph</h4><a onClick={() => setTab("Graph")}>View All →</a></div><EvidenceGraph data={graph} /></div>
                  </section>
                  <section className="row3">
                    <div className="card"><div className="ch"><h4><I n="evidence" />Evidence Files</h4>{Up}</div><EvTable /></div>
                    <div className="card"><div className="ch"><h4><I n="indicators" />Key Indicators</h4><a onClick={() => setTab("Indicators")}>View All →</a></div>
                      <div className="itabs">{IND_TABS.map(([k, l]) => <button key={k} className={indTab === k ? "on" : ""} onClick={() => setIndTab(k)}>{l}</button>)}</div>
                      {fInds.filter(i => i.type === indTab).slice(0, 5).map(IndRow)}
                      {!fInds.some(i => i.type === indTab) && <p className="muted pad">No indicators of this type.</p>}</div>
                    <div className="card"><div className="ch"><h4><I n="memory" />Historical Matches</h4><a onClick={() => setTab("Memory")}>View All →</a></div><MatchList mem={mem} /></div>
                  </section>
                </>);
                if (tab === "Evidence") return <div className="card" style={{ marginTop: 14 }}><div className="ch"><h4><I n="evidence" />Evidence Files</h4>{Up}</div><EvTable /></div>;
                if (tab === "Timeline") return <div className="card" style={{ marginTop: 14 }}><div className="ch"><h4><I n="timeline" />Investigation Timeline</h4></div><Timeline events={fTl} empty="No events found." /></div>;
                if (tab === "Indicators") return <div className="card" style={{ marginTop: 14 }}><div className="ch"><h4><I n="indicators" />All Indicators ({fInds.length})</h4></div>{fInds.length ? fInds.map(i => <div className="ir wide" key={i.id}><i className={`pt ${indMeta(i)[0]}`} /><span><small>{i.type}</small> {i.value}</span><span className={`tag ${indMeta(i)[0]}`}>{indMeta(i)[1]}</span><em>{i.source_evidence}</em></div>) : <p className="muted pad">No indicators detected.</p>}</div>;
                if (tab === "Memory") return <div className="card" style={{ marginTop: 14 }}><div className="ch"><h4><I n="memory" />Forensic Memory</h4></div><MatchList mem={mem} /></div>;
                if (tab === "Graph") return <div className="card" style={{ marginTop: 14 }}><div className="ch"><h4><I n="graph" />Evidence Graph</h4><span className="muted">cyan observed · red historical match · purple cross-case</span></div><EvidenceGraph data={graph} /></div>;
                return (
                    <div className="card" style={{ marginTop: 14 }}>
                      <div className="ch"><h4><I n="copilot" />Report &amp; AI Copilot</h4><button className="primary" onClick={explain} disabled={!!busy}>{busy === "ai" ? "Generating…" : "Generate Explanation"}</button></div>
                      <div className="report">
                        <h5>Risk level: <span className="yellow">{d.risk_level}</span> <small>(rule-based score {d.risk_score}, not a threat-severity standard)</small></h5>
                        <ul>{d.risk_reasons.length ? d.risk_reasons.map(r => <li key={r}>{r}</li>) : <li>No risk rules triggered.</li>}</ul>
                        {ai ? (<>
                          <h5>Observed evidence</h5><ul>{ai.observed.map((o, i) => <li key={i}>{o}</li>)}</ul>
                          <h5>Explanation <small>({ai.mode})</small></h5><p>{ai.text}</p>
                          {ai.inferred.length > 0 && <><h5>Inferred (not proof)</h5><ul>{ai.inferred.map((o, i) => <li key={i}>{o}</li>)}</ul></>}
                        </>) : <p className="muted">Generate an explanation built only from the deterministic findings above.</p>}
                      </div>
                    </div>
                );
              })()}
            </>)}
          </div>
        </main>
      </div>
  );
