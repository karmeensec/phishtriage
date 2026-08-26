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
}) {
  return (
    <section className="history-panel">
      <div className="history-heading">
        <div>
          <p className="eyebrow">ANALYSIS HISTORY</p>
          <h2>Recent email investigations</h2>
        </div>

        <span className="history-count">
          {total} total
        </span>
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

      {!isLoading && !error && items.length === 0 && (
        <p className="history-message">
          No emails have been analyzed yet.
        </p>
      )}

      {!isLoading && !error && items.length > 0 && (
        <div className="history-table-container">
          <table className="history-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Email</th>
                <th>Risk</th>
                <th>Findings</th>
                <th>Analyzed</th>
              </tr>
            </thead>

            <tbody>
              {items.map((item) => {
                const riskLevel = normalizeRiskLevel(
                  item.risk_level,
                );

                return (
                  <tr key={item.id}>
                    <td>#{item.id}</td>

                    <td>
                      <strong>{item.file_name}</strong>
                      <span className="history-subject">
                        {item.subject || "No subject"}
                      </span>
                      <span className="history-sender">
                        {item.sender || "Unknown sender"}
                      </span>
                    </td>

                    <td>
                      <span
                        className={
                          `severity severity-${riskLevel}`
                        }
                      >
                        {item.risk_score} · {riskLevel}
                      </span>
                    </td>

                    <td>{item.finding_count}</td>

                    <td>
                      {formatUtcTimestamp(
                        item.created_at,
                      )}
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