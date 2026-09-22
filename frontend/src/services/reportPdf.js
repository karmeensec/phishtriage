import { jsPDF } from "jspdf";


const PAGE_MARGIN = 16;
const PAGE_BOTTOM_MARGIN = 18;
const CONTENT_WIDTH = 178;


function createSafeFilename(value) {
  const withoutExtension = String(value || "analysis")
    .replace(/\.eml$/i, "");

  const sanitized = withoutExtension
    .replace(/[^a-z0-9._-]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);

  return sanitized || "analysis";
}


function makePdfSafe(value) {
  return String(value ?? "Not provided")
    .normalize("NFKD")
    .replace(/[^\x20-\x7E\n]/g, "?");
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


function normalizeReport(analysis) {
  const riskAssessment =
    analysis.risk_assessment ?? {};

  return {
    id: analysis.analysis_id ?? analysis.id ?? null,
    fileName:
      analysis.file ??
      analysis.file_name ??
      "Unknown file",
    subject: analysis.subject || "No subject",
    sender:
      analysis.from ??
      analysis.sender ??
      "Not provided",
    recipient: analysis.to || "Not provided",
    replyTo: analysis.reply_to || "Not provided",
    messageDate: analysis.date || "Not provided",
    createdAt:
      analysis.created_at || "Not provided",
    sha256:
      analysis.file_sha256 || "Not available",
    riskScore:
      riskAssessment.score ??
      analysis.risk_score ??
      0,
    riskLevel:
      riskAssessment.level ??
      analysis.risk_level ??
      "unknown",
    findingCount:
      riskAssessment.finding_count ??
      analysis.finding_count ??
      analysis.findings?.length ??
      0,
    authentication:
      analysis.header_analysis?.authentication ?? {},
    urlCount:
      analysis.url_analysis?.analyzed_count ?? 0,
    attachmentCount:
      analysis.attachment_analysis?.analyzed_count ??
      0,
    findings: analysis.findings ?? [],
  };
}


export function downloadPdfReport(
  analysis,
  filenameSource,
) {
  const report = normalizeReport(analysis);

  const document = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4",
  });

  const pageHeight =
    document.internal.pageSize.getHeight();

  let currentY = 18;

  function ensureSpace(requiredHeight) {
    if (
      currentY + requiredHeight >
      pageHeight - PAGE_BOTTOM_MARGIN
    ) {
      document.addPage();
      currentY = 18;
    }
  }

  function addWrappedText(
    value,
    {
      fontSize = 10,
      fontStyle = "normal",
      color = [30, 41, 59],
      indent = 0,
      spacingAfter = 3,
    } = {},
  ) {
    document.setFont(
      "helvetica",
      fontStyle,
    );

    document.setFontSize(fontSize);
    document.setTextColor(...color);

    const safeText = makePdfSafe(value);

    const lines = document.splitTextToSize(
      safeText,
      CONTENT_WIDTH - indent,
    );

    const lineHeight = fontSize * 0.42;

    ensureSpace(
      lines.length * lineHeight + spacingAfter,
    );

    document.text(
      lines,
      PAGE_MARGIN + indent,
      currentY,
    );

    currentY +=
      lines.length * lineHeight + spacingAfter;
  }

  function addSectionTitle(title) {
    ensureSpace(12);

    currentY += 3;

    document.setDrawColor(14, 116, 144);
    document.setLineWidth(0.6);

    document.line(
      PAGE_MARGIN,
      currentY,
      PAGE_MARGIN + CONTENT_WIDTH,
      currentY,
    );

    currentY += 7;

    addWrappedText(title, {
      fontSize: 14,
      fontStyle: "bold",
      color: [14, 116, 144],
      spacingAfter: 4,
    });
  }

  function addLabelValue(label, value) {
    addWrappedText(
      `${label}: ${value}`,
      {
        fontSize: 9,
        spacingAfter: 2,
      },
    );
  }

  document.setFillColor(8, 21, 37);

  document.rect(
    0,
    0,
    document.internal.pageSize.getWidth(),
    42,
    "F",
  );

  document.setTextColor(125, 211, 252);
  document.setFont("helvetica", "bold");
  document.setFontSize(22);

  document.text(
    "PhishTriage",
    PAGE_MARGIN,
    18,
  );

  document.setTextColor(226, 232, 240);
  document.setFontSize(11);

  document.text(
    "Phishing Email Investigation Report",
    PAGE_MARGIN,
    27,
  );

  document.setFontSize(8);
  document.setTextColor(148, 163, 184);

  document.text(
    makePdfSafe(
      `Generated ${new Date().toISOString()}`,
    ),
    PAGE_MARGIN,
    35,
  );

  currentY = 52;

  addWrappedText(report.subject, {
    fontSize: 17,
    fontStyle: "bold",
    color: [15, 23, 42],
    spacingAfter: 2,
  });

  addWrappedText(report.fileName, {
    fontSize: 9,
    color: [100, 116, 139],
    spacingAfter: 6,
  });

  document.setFillColor(241, 245, 249);

  document.roundedRect(
    PAGE_MARGIN,
    currentY,
    CONTENT_WIDTH,
    24,
    3,
    3,
    "F",
  );

  document.setTextColor(15, 23, 42);
  document.setFont("helvetica", "bold");
  document.setFontSize(18);

  document.text(
    `${report.riskScore}/100`,
    PAGE_MARGIN + 7,
    currentY + 10,
  );

  document.setFontSize(10);

  document.text(
    makePdfSafe(
      String(report.riskLevel).toUpperCase(),
    ),
    PAGE_MARGIN + 7,
    currentY + 18,
  );

  document.setFont("helvetica", "normal");

  document.text(
    makePdfSafe(
      `${report.findingCount} security findings`,
    ),
    PAGE_MARGIN + 65,
    currentY + 10,
  );

  document.text(
    makePdfSafe(
      `${report.urlCount} URLs | ` +
      `${report.attachmentCount} attachments`,
    ),
    PAGE_MARGIN + 65,
    currentY + 18,
  );

  currentY += 31;

  addSectionTitle("Email Information");

  if (report.id !== null) {
    addLabelValue("Analysis ID", report.id);
  }

  addLabelValue("From", report.sender);
  addLabelValue("To", report.recipient);
  addLabelValue("Reply-To", report.replyTo);
  addLabelValue("Message date", report.messageDate);

  if (report.createdAt !== "Not provided") {
    addLabelValue(
      "Analysis timestamp",
      report.createdAt,
    );
  }

  if (report.sha256 !== "Not available") {
    addLabelValue(
      "SHA-256",
      report.sha256,
    );
  }

  addSectionTitle("Email Authentication");

  addLabelValue(
    "SPF",
    report.authentication.spf ?? "Not available",
  );

  addLabelValue(
    "DKIM",
    report.authentication.dkim ?? "Not available",
  );

  addLabelValue(
    "DMARC",
    report.authentication.dmarc ?? "Not available",
  );

  addSectionTitle("Security Findings");

  if (report.findings.length === 0) {
    addWrappedText(
      "No suspicious indicators were detected.",
      {
        color: [71, 85, 105],
      },
    );
  }

  report.findings.forEach(
    (finding, index) => {
      ensureSpace(25);

      addWrappedText(
        `${index + 1}. ${finding.title}`,
        {
          fontSize: 11,
          fontStyle: "bold",
          color: [15, 23, 42],
          spacingAfter: 2,
        },
      );

      addWrappedText(
        `${finding.rule_id} | ` +
        `${finding.severity} | ` +
        `Score ${finding.score}`,
        {
          fontSize: 8,
          color: [71, 85, 105],
          indent: 3,
          spacingAfter: 2,
        },
      );

      if (finding.evidence) {
        Object.entries(finding.evidence).forEach(
          ([key, value]) => {
            addWrappedText(
              `${key.replaceAll("_", " ")}: ` +
              `${formatEvidenceValue(value)}`,
              {
                fontSize: 8,
                color: [51, 65, 85],
                indent: 6,
                spacingAfter: 1,
              },
            );
          },
        );
      }

      currentY += 4;
    },
  );

  const pageCount =
    document.getNumberOfPages();

  for (
    let pageNumber = 1;
    pageNumber <= pageCount;
    pageNumber += 1
  ) {
    document.setPage(pageNumber);

    document.setFont(
      "helvetica",
      "normal",
    );

    document.setFontSize(8);
    document.setTextColor(100, 116, 139);

    document.text(
      `PhishTriage | Page ${pageNumber} of ${pageCount}`,
      PAGE_MARGIN,
      pageHeight - 8,
    );

    document.text(
      "Defensive analysis report",
      PAGE_MARGIN + CONTENT_WIDTH,
      pageHeight - 8,
      {
        align: "right",
      },
    );
  }

  document.save(
    `${createSafeFilename(filenameSource)}-report.pdf`,
  );
}