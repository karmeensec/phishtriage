from backend.app.analyzers.body_analyzer import (
    analyze_body,
    normalize_text,
)


def get_rule_ids(result: dict) -> set[str]:
    return {
        finding["rule_id"]
        for finding in result["findings"]
    }


def test_legitimate_message_has_no_findings() -> None:
    result = analyze_body(
        subject="Weekly project update",
        body="The meeting notes are available for review.",
    )

    assert result["findings"] == []
    assert result["matched_category_count"] == 0


def test_detects_phishing_language() -> None:
    result = analyze_body(
        subject="Urgent account notice",
        body=(
            "Your account will be suspended. "
            "Verify your credentials immediately."
        ),
    )

    assert get_rule_ids(result) == {
        "BODY-URGENCY",
        "BODY-ACCOUNT",
        "BODY-CREDENTIALS",
    }


def test_repeated_urgency_does_not_inflate_score() -> None:
    result = analyze_body(
        subject="Urgent urgent urgent",
        body="Act now. This is your final warning.",
    )

    assert get_rule_ids(result) == {
        "BODY-URGENCY",
    }

    assert result["findings"][0]["score"] == 10


def test_detects_financial_and_action_language() -> None:
    result = analyze_body(
        subject="Payment request",
        body=(
            "Purchase a gift card and click here "
            "to provide the information."
        ),
    )

    assert get_rule_ids(result) == {
        "BODY-FINANCIAL",
        "BODY-ACTION",
    }


def test_unicode_text_is_normalized() -> None:
    normalized = normalize_text(
        "ＵＲＧＥＮＴ ACCOUNT NOTICE"
    )

    assert normalized == "urgent account notice"


def test_detects_cryptocurrency_lure_once() -> None:
    result = analyze_body(
        subject="Exclusive allocation",
        body=(
            "Review this cryptocurrency allocation "
            "and claim your tokens."
        ),
    )

    assert get_rule_ids(result) == {
        "BODY-FINANCIAL-LURE",
    }

    assert len(result["findings"]) == 1
    assert result["findings"][0]["score"] == 15