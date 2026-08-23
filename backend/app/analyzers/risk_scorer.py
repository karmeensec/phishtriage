from typing import Any


MAX_RISK_SCORE = 100

KNOWN_SEVERITIES = (
    "low",
    "medium",
    "high",
    "critical",
)


def determine_risk_level(score: int) -> str:
    """Convert a numeric risk score into a risk level."""

    if score >= 70:
        return "critical"

    if score >= 40:
        return "high"

    if score >= 20:
        return "medium"

    return "low"


def get_safe_finding_score(finding: dict[str, Any]) -> int:
    """Return a safe non-negative score from a finding."""

    score = finding.get("score", 0)

    # Reject malformed values and prevent negative risk reduction.
    if type(score) is not int:
        return 0

    return max(score, 0)


def calculate_risk(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Calculate a bounded and explainable phishing risk score."""

    uncapped_score = sum(
        get_safe_finding_score(finding)
        for finding in findings
    )

    # Keep the public score within the documented 0–100 range.
    final_score = min(uncapped_score, MAX_RISK_SCORE)

    severity_counts = {
        severity: 0
        for severity in KNOWN_SEVERITIES
    }

    for finding in findings:
        severity = str(
            finding.get("severity", "")
        ).lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

    return {
        "score": final_score,
        "uncapped_score": uncapped_score,
        "level": determine_risk_level(final_score),
        "finding_count": len(findings),
        "severity_counts": severity_counts,
    }