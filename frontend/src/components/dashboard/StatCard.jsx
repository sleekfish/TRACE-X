import { I } from "../icons";

export default function StatCard({ label, value, sub, icon, tone, risk = 0, reasons = [] }) {
  return (
    <div className={`stat ${tone}`} title={reasons.join("\n")}>
      <div className="sico"><I n={icon} /></div>
      <div>
        <small>{label}</small><strong>{value}</strong>
        {sub ? <span>{sub}</span> : <div className="bars">{[0, 1, 2, 3, 4, 5].map(k => <i key={k} className={k < risk ? "on" : ""} />)}</div>}
      </div>
    </div>
  );
}
