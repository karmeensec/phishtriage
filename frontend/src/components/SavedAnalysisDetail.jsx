import { downloadJsonReport } from "../services/reportExport.js";
import { downloadPdfReport } from "../services/reportPdf.js";

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

function formatEvidenceValue(value) {
  if (Array.isArray(value)) {
    return value
      .map((item) => formatEvidenceValue(item))
      .join(", ");
  }

  if (value && typeof value === "object") {
    return Object.entries(value)
      .map(([key, nestedValue]) => {
        const label = key.replaceAll("_", " ");

        return (
          `${label}: ` +
          formatEvidenceValue(nestedValue)
        );
      })
      .join(" | ");
  }

  return String(value ?? "Not provided");
}

function SavedAnalysisDetail({
  detail,
  isLoading,
  error,
  onClose,
}) {
  if (!detail && !isLoading && !error) {
    return null;
  }

  const riskLevel = detail
    ? normalizeRiskLevel(detail.risk_level)
    : "unknown";

  function handleJsonDownload() {
    if (!detail) {
      return;
    }

    downloadJsonReport(
      detail,
      detail.file_name,
    );
  }

  function handlePdfDownload() {
    if (!detail) {
      return;
    }

    downloadPdfReport(
      detail,
      detail.file_name,
    );
  }

  return (
    <section className="saved-detail result-panel">
      <div className="saved-detail-heading">
        <div>
          <p className="eyebrow">
            SAVED INVESTIGATION
          </p>

          <h2>
            {detail
              ? `Analysis #${detail.id}`
              : "Loading analysis"}
          </h2>
        </div>

        <div className="saved-detail-actions">
          {detail && !isLoading && (
            <button
              className="secondary-button"
              type="button"
              onClick={handleJsonDownload}
            >
              Download JSON report
            </button>
          )}

                  {detail && !isLoading && (
          <button
            className="secondary-button"
            type="button"
            onClick={handlePdfDownload}
          >
            Download PDF report
          </button>
        )}

          <button
            className="secondary-button"
            type="button"
            onClick={onClose}
          >
            Close
          </button>
        </div>
      </div>

      {isLoading && (
        <p className="history-message">
          Loading saved analysis…
        </p>
      )}

      {error && (
        <p className="error-message" role="alert">
          {error}
        </p>
      )}

      {detail && !isLoading && (
        <>
          <div className="saved-detail-summary">
            <div>
              <span>File</span>
              <strong>{detail.file_name}</strong>
            </div>

            <div>
              <span>Subject</span>
              <strong>
                {detail.subject || "No subject"}
              </strong>
            </div>

            <div>
              <span>Risk</span>
              <strong
                className={`risk-text-${riskLevel}`}
              >
                {detail.risk_score}/100 - {riskLevel}
              </strong>
            </div>

            <div>
              <span>Findings</span>
              <strong>{detail.finding_count}</strong>
            </div>
          </div>

          <div className="hash-panel">
            <span>SHA-256 fingerprint</span>
            <code>{detail.file_sha256}</code>
          </div>

          <section className="report-section">
            <h3>Saved security findings</h3>

            <div className="findings-list">
              {detail.findings.length === 0 ? (
                <p className="no-findings">
                  No suspicious indicators were
                  detected.
                </p>
              ) : (
                detail.findings.map(
                  (finding, index) => {
                    const severity =
                      normalizeRiskLevel(
                        finding.severity,
                      );

                    return (
                      <article
                        className="finding-card"
                        key={
                          `${finding.rule_id}-${index}`
                        }
                      >
                        <div className="finding-heading">
                          <div>
                            <span className="rule-id">
                              {finding.rule_id}
                            </span>

                            <h4>{finding.title}</h4>
                          </div>

                          <span
                            className={
                              `severity severity-${severity}`
                            }
                          >
                            {severity}
                          </span>
                        </div>

                        <div className="finding-score">
                          Rule score: {finding.score}
                        </div>

                        {finding.evidence && (
                          <dl className="evidence">
                            {Object.entries(
                              finding.evidence,
                            ).map(
                              ([key, value]) => (
                                <div key={key}>
                                  <dt>
                                    {key.replaceAll(
                                      "_",
                                      " ",
                                    )}
                                  </dt>

                                  <dd>
                                    {
                                      formatEvidenceValue(
                                        value,
                                      )
                                    }
                                  </dd>
                                </div>
                              ),
                            )}
                          </dl>
                        )}
                      </article>
                    );
                  },
                )
              )}
            </div>
          </section>
        </>
      )}
    </section>
  );
}

export default SavedAnalysisDetail;