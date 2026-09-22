import { downloadJsonReport } from "../services/reportExport.js";
import { downloadPdfReport } from "../services/reportPdf.js";

const RISK_LEVELS = [
  "low",
  "medium",
  "high",
  "critical",
];

const AUTH_RESULTS = [
  "pass",
  "fail",
  "neutral",
  "unknown",
];

function normalizeRiskLevel(level) {
  const normalized = String(level).toLowerCase();

  return RISK_LEVELS.includes(normalized)
    ? normalized
    : "unknown";
}

function normalizeAuthResult(result) {
  const normalized = String(
    result ?? "unknown",
  ).toLowerCase();

  return AUTH_RESULTS.includes(normalized)
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

function AnalysisReport({ result }) {
  const risk = result.risk_assessment;
  const riskLevel = normalizeRiskLevel(risk.level);

  const authentication =
    result.header_analysis?.authentication ?? {};

  function handleJsonDownload() {
    downloadJsonReport(
      result,
      result.file,
    );
  }

  function handlePdfDownload() {
  downloadPdfReport(
    result,
    result.file,
  );
}

  return (
    <section
      className="result-panel"
      aria-live="polite"
    >
      <div className="report-heading">
        <div>
          <p className="eyebrow">ANALYSIS COMPLETE</p>
          <h2>{result.subject || "No subject"}</h2>
          <p className="report-file">{result.file}</p>
        </div>

        <div className="report-actions">
          <div className={`risk-score risk-${riskLevel}`}>
            <strong>{risk.score}</strong>
            <span>/ 100</span>
            <small>{riskLevel}</small>
          </div>

          <button
            className="secondary-button"
            type="button"
            onClick={handleJsonDownload}
          >
            Download JSON report
          </button>

          <button
            className="secondary-button"
            type="button"
            onClick={handlePdfDownload}
            >
            Download PDF report
          </button>
        </div>
      </div>

      <div className="summary-grid">
        <div className="summary-card">
          <span>Total findings</span>
          <strong>{risk.finding_count}</strong>
        </div>

        <div className="summary-card">
          <span>High severity</span>
          <strong>
            {risk.severity_counts?.high ?? 0}
          </strong>
        </div>

        <div className="summary-card">
          <span>URLs analyzed</span>
          <strong>
            {result.url_analysis?.analyzed_count ?? 0}
          </strong>
        </div>

        <div className="summary-card">
          <span>Attachments</span>
          <strong>
            {
              result.attachment_analysis
                ?.analyzed_count ?? 0
            }
          </strong>
        </div>
      </div>

      <section className="report-section">
        <h3>Email information</h3>

        <dl className="details-grid">
          <div>
            <dt>From</dt>
            <dd>{result.from || "Not provided"}</dd>
          </div>

          <div>
            <dt>To</dt>
            <dd>{result.to || "Not provided"}</dd>
          </div>

          <div>
            <dt>Reply-To</dt>
            <dd>
              {result.reply_to || "Not provided"}
            </dd>
          </div>

          <div>
            <dt>Date</dt>
            <dd>{result.date || "Not provided"}</dd>
          </div>

          <div>
            <dt>Sender domain</dt>
            <dd>
              {
                result.header_analysis
                  ?.sender_domain || "Not available"
              }
            </dd>
          </div>

          <div>
            <dt>Reply-To domain</dt>
            <dd>
              {
                result.header_analysis
                  ?.reply_to_domain || "Not available"
              }
            </dd>
          </div>
        </dl>
      </section>

      <section className="report-section">
        <h3>Email authentication</h3>

        <div className="authentication-grid">
          {["spf", "dkim", "dmarc"].map(
            (mechanism) => {
              const authResult =
                normalizeAuthResult(
                  authentication[mechanism],
                );

              return (
                <div
                  className="authentication-card"
                  key={mechanism}
                >
                  <span>
                    {mechanism.toUpperCase()}
                  </span>

                  <strong
                    className={`auth-${authResult}`}
                  >
                    {authResult}
                  </strong>
                </div>
              );
            },
          )}
        </div>
      </section>

      <section className="report-section">
        <h3>Security findings</h3>

        <div className="findings-list">
          {result.findings.length === 0 ? (
            <p className="no-findings">
              No suspicious indicators were detected.
            </p>
          ) : (
            result.findings.map(
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
                        ).map(([key, value]) => (
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
                        ))}
                      </dl>
                    )}
                  </article>
                );
              },
            )
          )}
        </div>
      </section>
    </section>
  );
}

export default AnalysisReport;