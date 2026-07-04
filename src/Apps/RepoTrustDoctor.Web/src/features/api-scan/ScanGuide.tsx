const profileGuide = [
  [
    'Personal project',
    'Use this for experiments, learning projects, prototypes, or tools that do not protect production data. Findings still appear, but the final judgment is less strict.'
  ],
  [
    'Production dependency',
    'Use this when the repository may become a library, service, tool, image, or build input that another production system depends on.'
  ],
  [
    'Enterprise or security-sensitive',
    'Use this for organization-wide adoption, authentication, cryptography, authorization, secret handling, infrastructure control, or other high-impact code.'
  ]
];

const depthGuide = [
  ['Fast scan', 'Broad repository, dependency, CI/CD, secret, container, infrastructure, and release checks with bounded file scanning.'],
  ['Standard scan', 'The default review depth for adoption decisions that need more complete static evidence.'],
  ['Deep scan', 'Adds deeper code intelligence such as public API, import graph, routes, critical paths, and imported coverage evidence.']
];

export function ScanGuide() {
  return (
    <aside className="scan-guide" aria-label="Scan option guide">
      <section>
        <h2>Profile guide</h2>
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
        <h2>Depth guide</h2>
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
