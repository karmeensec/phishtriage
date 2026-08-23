from backend.app.analyzers.risk_scorer import (
    calculate_risk,
    determine_risk_level,
)


def test_empty_findings_produce_low_risk() -> None:
    result = calculate_risk([])

    assert result["score"] == 0
    assert result["level"] == "low"
    assert result["finding_count"] == 0


def test_risk_level_boundaries() -> None:
    cases = [
        (0, "low"),
        (19, "low"),
        (20, "medium"),
        (39, "medium"),
        (40, "high"),
        (69, "high"),
        (70, "critical"),
        (100, "critical"),
    ]

    for score, expected_level in cases:
        assert determine_risk_level(score) == expected_level


def test_risk_score_is_capped_at_100() -> None:
    findings = [
        {"score": 75, "severity": "high"},
        {"score": 75, "severity": "high"},
    ]

    result = calculate_risk(findings)

    assert result["uncapped_score"] == 150
    assert result["score"] == 100
    assert result["level"] == "critical"


def test_invalid_scores_cannot_corrupt_result() -> None:
    findings = [
        {"score": -50, "severity": "low"},
        {"score": "25", "severity": "medium"},
        {"score": None, "severity": "high"},
        {"score": 20, "severity": "medium"},
    ]

    result = calculate_risk(findings)

    assert result["score"] == 20
    assert result["level"] == "medium"


def test_severity_counts_are_calculated() -> None:
    findings = [
        {"score": 10, "severity": "medium"},
        {"score": 25, "severity": "high"},
        {"score": 25, "severity": "high"},
    ]

    result = calculate_risk(findings)

    assert result["severity_counts"] == {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 0,
    }