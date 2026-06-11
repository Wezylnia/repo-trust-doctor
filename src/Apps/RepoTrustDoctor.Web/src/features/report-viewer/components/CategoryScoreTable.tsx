import type { RepositoryScan } from '../../../domain/report';
import { buildAreaScores, formatCategory, scoreTone } from '../../../domain/reportSelectors';

export function CategoryScoreTable({ report }: { report: RepositoryScan }) {
  const areas = buildAreaScores(report);

  if (!areas.length) {
    return null;
  }

  return (
    <section className="summary-panel area-score-panel" aria-label="Area scores">
      <div className="panel-heading">
        <div>
          <h2>Area scores</h2>
          <span>How the repository scored across the main review areas.</span>
        </div>
      </div>
      <div className="area-score-grid">
        {areas.map((area) => (
          <div className={`area-score-card ${scoreTone(area.score)}`} key={area.id}>
            <div>
              <strong>{area.label}</strong>
              <span>{area.description}</span>
            </div>
            <div className="area-score-value">
              <b>{area.score}</b>
              <span>/100</span>
            </div>
            <meter min={0} max={100} value={area.score} aria-label={`${area.label} score`} />
            <small>{area.categories.map(formatCategory).join(', ')}</small>
          </div>
        ))}
      </div>
    </section>
  );
}
