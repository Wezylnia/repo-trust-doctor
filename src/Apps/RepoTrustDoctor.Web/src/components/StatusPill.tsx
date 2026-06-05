import { AlertTriangle, CheckCircle2 } from 'lucide-react';

export function StatusPill({ status, count }: { status: string; count: number }) {
  const completed = status.toLowerCase().startsWith('completed');
  return (
    <span className={`status-pill ${completed ? 'completed' : ''}`}>
      {completed ? <CheckCircle2 size={14} aria-hidden="true" /> : <AlertTriangle size={14} aria-hidden="true" />}
      {count}
    </span>
  );
}
