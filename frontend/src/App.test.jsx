import {
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import {
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import App from "./App.jsx";
import { analyzeEmail } from "./services/api.js";

vi.mock("./services/api.js", () => ({
  analyzeEmail: vi.fn(),
}));

const analysisResult = {
  file: "phishing_email.eml",
  subject: "Suspicious account verification",
  from: "attacker@example.test",
  to: "analyst@example.test",
  reply_to: "attacker@example.test",
  date: "Wed, 19 Aug 2026 09:00:00 -0500",
  header_analysis: {
    sender_domain: "example.test",
    reply_to_domain: "example.test",
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
  findings: [],
  risk_assessment: {
    score: 80,
    level: "high",
    finding_count: 0,
    severity_counts: {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    },
  },
};

describe("App", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("uploads an email and displays its analysis", async () => {
    analyzeEmail.mockResolvedValue(analysisResult);

    render(<App />);

    const analyzeButton = screen.getByRole("button", {
      name: "Analyze Email",
    });

    expect(analyzeButton).toBeDisabled();

    const file = new File(
      ["From: attacker@example.test"],
      "phishing_email.eml",
      { type: "message/rfc822" },
    );

    fireEvent.change(
      screen.getByLabelText("Select an .eml file"),
      {
        target: { files: [file] },
      },
    );

    expect(analyzeButton).toBeEnabled();
    fireEvent.click(analyzeButton);

    await waitFor(() => {
      expect(analyzeEmail).toHaveBeenCalledWith(file);
    });

    expect(
      await screen.findByText("Suspicious account verification"),
    ).toBeInTheDocument();
  });

  it("shows a safe error message when analysis fails", async () => {
    analyzeEmail.mockRejectedValue(
      new Error("Analysis service unavailable."),
    );

    render(<App />);

    const file = new File(
      ["From: attacker@example.test"],
      "failed_email.eml",
      { type: "message/rfc822" },
    );

    fireEvent.change(
      screen.getByLabelText("Select an .eml file"),
      {
        target: { files: [file] },
      },
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: "Analyze Email",
      }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Analysis service unavailable.",
    );
  });
});