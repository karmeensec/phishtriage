import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import AnalysisReport from "./AnalysisReport.jsx";

const phishingResult = {
  file: "phishing_email.eml",
  subject: "Urgent: Verify your account immediately",
  from: "Security Team <security@example.test>",
  to: "analyst@example.test",
  reply_to: "attacker@example.test",
  date: "Wed, 19 Aug 2026 09:00:00 -0500",
  header_analysis: {
    sender_domain: "example.test",
    reply_to_domain: "attacker.example.test",
    authentication: {
      spf: "fail",
      dkim: "fail",
      dmarc: "fail",
    },
  },
  url_analysis: {
    analyzed_count: 1,
  },
  attachment_analysis: {
    analyzed_count: 0,
  },
  findings: [
    {
      rule_id: "HDR-001",
      title: "Sender and Reply-To domains do not match",
      severity: "high",
      score: 25,
      evidence: {
        sender_domain: "example.test",
        reply_to_domain: "attacker.example.test",
      },
    },
  ],
  risk_assessment: {
    score: 100,
    level: "critical",
    finding_count: 1,
    severity_counts: {
      low: 0,
      medium: 0,
      high: 1,
      critical: 0,
    },
  },
};

describe("AnalysisReport", () => {
  it("displays the risk assessment and security findings", () => {
    render(<AnalysisReport result={phishingResult} />);

    expect(screen.getByText("100")).toBeInTheDocument();

    expect(
      screen.getByText(
        "Sender and Reply-To domains do not match",
      ),
    ).toBeInTheDocument();

    expect(screen.getByText("HDR-001")).toBeInTheDocument();
    expect(screen.getAllByText("fail")).toHaveLength(3);
  });

  it("renders suspicious HTML as text instead of executing it", () => {
    const maliciousSubject = "<img src=x onerror=alert(1)>";

    render(
      <AnalysisReport
        result={{
          ...phishingResult,
          subject: maliciousSubject,
        }}
      />,
    );

    expect(
      screen.getByText(maliciousSubject),
    ).toBeInTheDocument();

    expect(
      document.querySelector("img"),
    ).not.toBeInTheDocument();
  });
});