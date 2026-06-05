import { useMemo, useState } from 'react';
import type { Finding } from '../../domain/report';
import { recommendationText, severityOrder } from '../../domain/reportSelectors';

export function useFindingFilters(findings: Finding[]) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('All');
  const [category, setCategory] = useState('All');

  const categories = useMemo(() => ['All', ...Array.from(new Set(findings.map((finding) => finding.category))).sort()], [findings]);

  const filteredFindings = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    return findings
      .filter((finding) => severity === 'All' || finding.severity === severity)
      .filter((finding) => category === 'All' || finding.category === category)
      .filter((finding) => {
        if (!normalizedQuery) return true;
        return [
          finding.ruleId,
          finding.title,
          finding.category,
          finding.severity,
          finding.message,
          recommendationText(finding),
          ...(finding.tags ?? []),
          ...finding.evidence.flatMap((evidence) => [
            evidence.kind,
            evidence.message,
            evidence.filePath ?? '',
            evidence.value ?? ''
          ])
        ]
          .join(' ')
          .toLowerCase()
          .includes(normalizedQuery);
      })
      .sort((left, right) => {
        const severityDelta = (severityOrder[right.severity] ?? 0) - (severityOrder[left.severity] ?? 0);
        if (severityDelta !== 0) return severityDelta;
        return left.ruleId.localeCompare(right.ruleId);
      });
  }, [category, findings, query, severity]);

  return {
    categories,
    category,
    filteredFindings,
    query,
    severity,
    setCategory,
    setQuery,
    setSeverity,
    clearFilters: () => {
      setQuery('');
      setSeverity('All');
      setCategory('All');
    }
  };
}
