import asyncio

from pytest import MonkeyPatch

from backend.app.services import url_reputation


def test_reputation_is_disabled_without_configuration(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        "URL_REPUTATION_ENABLED",
        raising=False,
    )
    monkeypatch.delenv(
        "VIRUSTOTAL_API_KEY",
        raising=False,
    )

    result = asyncio.run(
        url_reputation.analyze_url_reputation(
            ["https://suspicious.example/login"]
        )
    )

    assert result["enabled"] is False
    assert result["findings"] == []


def test_extracts_unique_public_domains() -> None:
    result = url_reputation.extract_public_domains(
        [
            "https://portal.example.com/login",
            "https://portal.example.com/reset",
            "http://192.0.2.10/login",
            "https://localhost/test",
            "https://testing.example/path",
        ]
    )

    assert result == ["portal.example.com"]


def test_flagged_domain_creates_one_finding(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "URL_REPUTATION_ENABLED",
        "true",
    )
    monkeypatch.setenv(
        "VIRUSTOTAL_API_KEY",
        "test-api-key",
    )

    def fake_report(
        domain: str,
        api_key: str,
    ) -> dict[str, int]:
        assert domain == "malicious.example.net"
        assert api_key == "test-api-key"

        return {
            "malicious": 4,
            "suspicious": 2,
            "harmless": 10,
            "undetected": 20,
        }

    monkeypatch.setattr(
        url_reputation,
        "_fetch_domain_report",
        fake_report,
    )

    result = asyncio.run(
        url_reputation.analyze_url_reputation(
            [
                "https://malicious.example.net/login",
                "https://malicious.example.net/reset",
            ]
        )
    )

    assert result["enabled"] is True
    assert result["checked_domain_count"] == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["rule_id"] == (
        "URL-REPUTATION"
    )
    assert result["findings"][0]["severity"] == "high"
    assert result["findings"][0]["score"] == 30


def test_reputation_failure_does_not_break_analysis(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "URL_REPUTATION_ENABLED",
        "true",
    )
    monkeypatch.setenv(
        "VIRUSTOTAL_API_KEY",
        "test-api-key",
    )

    monkeypatch.setattr(
        url_reputation,
        "_fetch_domain_report",
        lambda domain, api_key: None,
    )

    result = asyncio.run(
        url_reputation.analyze_url_reputation(
            ["https://unknown.example.net/login"]
        )
    )

    assert result["enabled"] is True
    assert result["checked_domain_count"] == 0
    assert result["findings"] == []