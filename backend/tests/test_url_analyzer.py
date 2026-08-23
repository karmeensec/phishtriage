from backend.app.analyzers.url_analyzer import analyze_url


def get_rule_ids(result: dict) -> set[str]:
    return {
        finding["rule_id"]
        for finding in result["findings"]
    }


def test_normal_https_url_has_no_findings() -> None:
    result = analyze_url(
        "https://portal.example.com/security"
    )

    assert result["hostname"] == "portal.example.com"
    assert result["findings"] == []


def test_detects_unencrypted_http() -> None:
    result = analyze_url(
        "http://portal.example.com/login"
    )

    assert get_rule_ids(result) == {"URL-HTTP"}


def test_detects_ip_address_url() -> None:
    result = analyze_url(
        "https://192.0.2.10/login"
    )

    assert get_rule_ids(result) == {"URL-IP"}


def test_detects_embedded_user_information() -> None:
    result = analyze_url(
        "https://trusted.example@evil.example/login"
    )

    assert result["hostname"] == "evil.example"
    assert get_rule_ids(result) == {"URL-CREDENTIALS"}


def test_detects_punycode_domain() -> None:
    result = analyze_url(
        "https://xn--example-9za.example/login"
    )

    assert get_rule_ids(result) == {"URL-PUNYCODE"}