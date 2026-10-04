import { P } from "../icons";

export default function EvidenceGraph({ data }) {
  if (!data || data.nodes.length < 2) return <p className="muted pad">Analyze evidence to build the relationship graph.</p>;
  const col = n => (n.current ? 0 : n.kind === "domain" ? 1 : n.kind === "ip" ? 2 : n.kind === "file" ? 3 : 4);
  const cols = [[], [], [], [], []]; data.nodes.forEach(n => cols[col(n)].push(n));
  const pos = {}; cols.forEach((c, ci) => c.forEach((n, i) => { pos[n.id] = [55 + ci * 112, ((i + 1) * 290) / (c.length + 1)]; }));
  const icon = { case: "monitor", ip: "globe", domain: "globe", file: "evidence" };
  return (
    <svg className="graph" viewBox="0 0 560 290">
      {data.edges.map((e, i) => pos[e.source] && pos[e.target] && (
        <line key={i} className={`gl ${e.tone}`} x1={pos[e.source][0]} y1={pos[e.source][1]} x2={pos[e.target][0]} y2={pos[e.target][1]} />
      ))}
      {data.nodes.map(n => {
        const [x, y] = pos[n.id];
        return (
          <g key={n.id} className={`gn ${n.tone}`}>
            <circle cx={x} cy={y} r="22" />
            <svg x={x - 9} y={y - 9} width="18" height="18" viewBox="0 0 24 24" className="gi">{P[icon[n.kind]].split("|").map((d, k) => <path key={k} d={d} />)}</svg>
            <text x={x} y={y + 38} textAnchor="middle" className="gt">{n.label.length > 17 ? n.label.slice(0, 16) + "…" : n.label}</text>
          </g>
        );
      })}
    </svg>
  );
}
