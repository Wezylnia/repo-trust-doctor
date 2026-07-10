const profileGuide = [
  [
    '1. Name the repository',
    'Paste owner/repository. We scan the public GitHub source through your local API.'
  ],
  [
    '2. Choose the decision context',
    'Select the risk level that matches how you plan to use it. Production and security-sensitive profiles require stronger evidence.'
  ],
  [
    '3. Review the recommendation',
    'Start with the decision and next steps, then inspect evidence or export a team-ready report.'
  ]
];

const depthGuide = [
  ['Fast', 'A quick first look when you need an initial signal.'],
  ['Standard', 'Recommended for most adoption decisions: broader evidence without deep code analysis.'],
  ['Deep', 'For high-impact decisions: adds API, route, import graph, critical-code, and coverage evidence.']
];

export function ScanGuide() {
  return (
    <aside className="scan-guide" aria-label="Scan option guide">
      <section>
        <h2>From repository to decision</h2>
        <div className="guide-list">
          {profileGuide.map(([title, description]) => (
            <div className="guide-row" key={title}>
              <strong>{title}</strong>
              <span>{description}</span>
            </div>
          ))}
        </div>
      </section>
      <section>
        <h2>Choose enough evidence</h2>
        <div className="guide-list">
          {depthGuide.map(([title, description]) => (
            <div className="guide-row" key={title}>
              <strong>{title}</strong>
              <span>{description}</span>
            </div>
          ))}
        </div>
      </section>
    </aside>
  );
}
