import { I } from "../icons";

const STY = { "DNS QUERY": ["globe", "blue"], "DNS RESPONSE": ["download", "green"], "TCP CONNECTION": ["net", "purple"], HTTP: ["evidence", "red"] };
const evStyle = t => STY[t] || (t.startsWith("FILE") ? ["evidence", "yellow"] : ["timeline", "blue"]);
const cap = s => s.charAt(0) + s.slice(1).toLowerCase();

export default function Timeline({ events, empty }) {
  if (!events.length) return <p className="muted pad">{empty}</p>;
  return events.map(e => {
    const [ic, c] = evStyle(e.event_type);
    return (
      <div className="ev" key={e.id}>
        <span className="t">{(e.timestamp || "").slice(11, 19)}</span><i className={`pt ${c}`} />
        <div className={`eico ${c}`}><I n={ic} /></div>
        <div className="ed"><b className={c}>{cap(e.event_type)}</b><code>{e.description}</code></div>
        <span className="r">{e.src_ip || ""}</span>
      </div>
    );
  });
}
