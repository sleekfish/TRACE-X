import { I } from "../icons";

const nav = [["Dashboard", "dashboard"], ["Cases", "cases"], ["Evidence", "evidence"], ["Timeline", "timeline"], ["Indicators", "indicators"], ["Memory", "memory"], ["Graph", "graph"], ["Reports", "evidence"]];

export default function Sidebar({ navSel, onNav, onSettings }) {
  return (
    <aside className="sidebar">
      <div className="brand"><h1>TRACE-<em>X</em></h1><b>MEMORY</b><small>Digital Investigation &amp; Cross-Incident Intelligence</small></div>
      <nav>
        {nav.map(([l, ic]) => <button key={l} className={navSel === l ? "on" : ""} onClick={() => onNav(l, l === "Dashboard" || l === "Cases" ? "Overview" : l)}><I n={ic} />{l}</button>)}
        <hr />
        <button className={navSel === "AI Copilot" ? "on" : ""} onClick={() => onNav("AI Copilot", "Reports")}><I n="copilot" />AI Copilot<span className="pro">PRO</span></button>
        <button onClick={onSettings}><I n="settings" />Settings</button>
      </nav>
      <div className="side-bottom"><span>System Operational</span><p><i />All services online</p><small>TRACE-X v0.1.0</small></div>
    </aside>
  );
}
