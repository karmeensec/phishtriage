const RISK_LEVELS = [
  "low",
  "medium",
  "high",
  "critical",
];

function normalizeRiskLevel(level) {
  const normalized = String(level).toLowerCase();

  return RISK_LEVELS.includes(normalized)
    ? normalized
    : "unknown";
}

function formatUtcTimestamp(value) {
  const timestamp = new Date(value);

  if (Number.isNaN(timestamp.getTime())) {
    return "Unknown time";
  }

  return `${new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(timestamp)} UTC`;
}

function HistoryPanel({
  items,
  total,
  isLoading,
  error,
  selectedId,
  isSelectionLoading,
  search,
  riskLevel,
  onSearchChange,
  onRiskLevelChange,
  onClearFilters,
  onSelect,
}) {
  const hasFilters = Boolean(
    search.trim() || riskLevel,
  );

  return (
    <section className="history-panel">
      <div className="history-heading">
        <div>
          <p className="eyebrow">
            ANALYSIS HISTORY
          </p>

          <h2>Recent email investigations</h2>
        </div>

        <span className="history-count">
          {total} {hasFilters ? "matching" : "total"}
        </span>
      </div>

      <div className="history-filters">
        <label className="history-filter-field">
          <span>Search investigations</span>

          <input
            type="search"
            maxLength={200}
            placeholder="Filename, subject, or sender"
            value={search}
            onChange={(event) => {
              onSearchChange(event.target.value);
            }}
          />
        </label>

        <label className="history-filter-field">
          <span>Risk level</span>

          <select
            value={riskLevel}
            onChange={(event) => {
              onRiskLevelChange(
                event.target.value,
              );
            }}
          >
            <option value="">All risk levels</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">
              Critical
            </option>
          </select>
        </label>

        <button
          className="secondary-button history-clear-button"
          type="button"
          disabled={!hasFilters}
          onClick={onClearFilters}
        >
          Clear filters
        </button>
      </div>

      {isLoading && (
        <p className="history-message">
          Loading analysis history…
        </p>
      )}

      {error && (
        <p className="error-message" role="alert">
          {error}
        </p>
      )}

      {!isLoading &&
        !error &&
        items.length === 0 && (
          <p className="history-message">
            {hasFilters
              ? "No investigations match these filters."
              : "No emails have been analyzed yet."}
          </p>
        )}

      {!isLoading &&
        !error &&
        items.length > 0 && (
          <div className="history-table-container">
            <table className="history-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Email</th>
                  <th>Risk</th>
                  <th>Findings</th>
                  <th>Analyzed</th>
                  <th>Action</th>
                </tr>
              </thead>

              <tbody>
                {items.map((item) => {
                  const normalizedRiskLevel =
                    normalizeRiskLevel(
                      item.risk_level,
                    );

                  return (
                    <tr key={item.id}>
                      <td>#{item.id}</td>

                      <td>
                        <strong>
                          {item.file_name}
                        </strong>

                        <span className="history-subject">
                          {item.subject ||
                            "No subject"}
                        </span>

                        <span className="history-sender">
                          {item.sender ||
                            "Unknown sender"}
                        </span>
                      </td>

                      <td>
                        <span
                          className={
                            `severity severity-${normalizedRiskLevel}`
                          }
                        >
                          {item.risk_score} ·{" "}
                          {normalizedRiskLevel}
                        </span>
                      </td>

                      <td>
                        {item.finding_count}
                      </td>

                      <td>
                        {formatUtcTimestamp(
                          item.created_at,
                        )}
                      </td>

                      <td>
                        <button
                          className="history-view-button"
                          type="button"
                          disabled={
                            isSelectionLoading
                          }
                          onClick={() => {
                            onSelect(item.id);
                          }}
                        >
                          {selectedId === item.id
                            ? "Selected"
                            : "View"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
    </section>
  );
}

export default HistoryPanel;