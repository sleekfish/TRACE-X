import { I } from "../icons";
import { useTheme } from "../../context/ThemeContext";

export default function Topbar({ q, setQ, hasAlert, onBell }) {
  const { toggle } = useTheme();
  return (
    <header className="topbar">
      <label className="search"><I n="search" /><input value={q} onChange={e => setQ(e.target.value)} placeholder="Search cases, indicators, evidence..." /><kbd>Ctrl K</kbd></label>
      <div className="top-right">
        <button className="ib" onClick={onBell}><I n="bell" />{hasAlert && <i className="dot" />}</button>
        <button className="ib" onClick={toggle}><I n="sun" /></button>
        <div className="user"><span>K</span>Kunal Dubey</div>
      </div>
    </header>
  );
}
