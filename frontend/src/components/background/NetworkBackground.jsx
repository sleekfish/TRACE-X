const nodes = [
  [8, 14, "red"], [20, 38, "cyan"], [31, 12, "red"], [43, 30, "cyan"], [54, 10, "red"],
  [64, 36, "purple"], [74, 14, "red"], [84, 40, "cyan"], [93, 18, "red"],
  [10, 66, "cyan"], [26, 84, "red"], [40, 68, "cyan"], [55, 86, "purple"],
  [69, 70, "red"], [82, 88, "cyan"], [94, 64, "red"],
];
const links = [[0,1],[1,3],[0,2],[2,3],[2,4],[3,5],[4,6],[5,6],[5,7],[6,8],[7,8],[1,9],[3,11],[9,10],[10,11],[11,12],[12,13],[13,14],[13,15],[7,13],[5,11],[14,15]];

export default function NetworkBackground() {
  return (
    <div className="network-background" aria-hidden="true">
      <div className="network-grid" />
      <svg className="network-svg" viewBox="0 0 100 100" preserveAspectRatio="none">
        {links.map(([a, b], i) => (
          <line key={i} x1={nodes[a][0]} y1={nodes[a][1]} x2={nodes[b][0]} y2={nodes[b][1]} />
        ))}
      </svg>
      {nodes.map(([x, y, c], i) => (
        <span key={i} className={`network-node ${c}`} style={{ left: `${x}%`, top: `${y}%`, animationDelay: `${(i * 0.7) % 4}s` }} />
      ))}
      <div className="network-glow" />
    </div>
  );
}
