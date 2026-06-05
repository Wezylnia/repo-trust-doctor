interface MetricProps {
  label: string;
  value: number;
  tone?: string;
}

export function Metric({ label, value, tone }: MetricProps) {
  return (
    <div className={`metric ${tone ?? ''}`}>
      <span>{value}</span>
      <small>{label}</small>
    </div>
  );
}
