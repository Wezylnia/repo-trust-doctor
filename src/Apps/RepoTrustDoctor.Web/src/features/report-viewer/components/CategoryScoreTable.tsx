import type { RepositoryScan } from '../../../domain/report';

export function CategoryScoreTable({ report }: { report: RepositoryScan }) {
  if (!report.score.categories.length) {
    return null;
  }

  return (
    <section className="summary-panel" aria-label="Category scores">
      <h2>Category scores</h2>
      <div className="score-table">
        {report.score.categories.map((item) => (
          <div className="score-table-row" key={item.category}>
            <span>{item.category}</span>
            <meter min={0} max={100} value={item.score} aria-label={`${item.category} score`} />
            <strong>{item.score}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}
