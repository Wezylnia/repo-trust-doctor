import { Search, X } from 'lucide-react';
import { formatCategory, severities } from '../../../domain/reportSelectors';

interface FilterToolbarProps {
  categories: string[];
  category: string;
  query: string;
  severity: string;
  actionableOnly: boolean;
  groupRepeated: boolean;
  onCategoryChange: (value: string) => void;
  onClear: () => void;
  onQueryChange: (value: string) => void;
  onSeverityChange: (value: string) => void;
  onActionableOnlyChange: (value: boolean) => void;
  onGroupRepeatedChange: (value: boolean) => void;
}

export function FilterToolbar({
  categories,
  category,
  query,
  severity,
  actionableOnly,
  groupRepeated,
  onCategoryChange,
  onClear,
  onQueryChange,
  onSeverityChange,
  onActionableOnlyChange,
  onGroupRepeatedChange
}: FilterToolbarProps) {
  return (
    <div className="toolbar" aria-label="Finding filters">
      <label className="search-field">
        <Search size={16} aria-hidden="true" />
        <input
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder="Search findings, files, rules"
        />
      </label>
      <select value={severity} onChange={(event) => onSeverityChange(event.target.value)} aria-label="Severity">
        {severities.map((item) => (
          <option value={item} key={item}>
            {item}
          </option>
        ))}
      </select>
      <select value={category} onChange={(event) => onCategoryChange(event.target.value)} aria-label="Category">
        {categories.map((item) => (
          <option value={item} key={item}>
            {item === 'All' ? 'All' : formatCategory(item)}
          </option>
        ))}
      </select>
      <label className="filter-toggle">
        <input type="checkbox" checked={actionableOnly} onChange={(event) => onActionableOnlyChange(event.target.checked)} />
        Actionable only
      </label>
      <label className="filter-toggle">
        <input type="checkbox" checked={groupRepeated} onChange={(event) => onGroupRepeatedChange(event.target.checked)} />
        Group repeated
      </label>
      <button type="button" className="icon-button" onClick={onClear} aria-label="Clear filters" title="Clear filters">
        <X size={16} aria-hidden="true" />
      </button>
    </div>
  );
}
