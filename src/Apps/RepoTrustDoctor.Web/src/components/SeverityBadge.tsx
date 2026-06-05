export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`severity-badge ${severity.toLowerCase()}`}>{severity}</span>;
}
