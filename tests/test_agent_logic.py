"""Tests for SOC AutoPilot's pure logic.

These cover the parts that decide what a finding *is* -- IOC extraction,
threat-level mapping, private-IP detection, and the knowledge base's
similarity search -- with no network, no API keys, and no Splunk.

The agent's own pipeline needs all of those, so the behaviour that matters
most (does it read the right things out of an alert?) was previously
untestable and therefore untested.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.autopilot import AutoPilotAgent  # noqa: E402
from agent.knowledge_base import KnowledgeBase  # noqa: E402
from agent.threat_intel import ThreatIntel  # noqa: E402


@pytest.fixture(scope="module")
def agent() -> AutoPilotAgent:
    """An agent with no API keys configured.

    Every dependency is initialised through a _safe_init_* helper, so the
    agent constructs cleanly with no Splunk, no LLM key and no
    ABUSEIPDB_API_KEY. That is exactly the situation a user hits when they
    clone the repo, so it is worth having a test for it.
    """
    return AutoPilotAgent({})


class TestIOCExtraction:
    def test_extracts_ipv4_addresses(self, agent: AutoPilotAgent) -> None:
        iocs = agent.extract_iocs(
            "Multiple failed logins from 192.168.1.100 and 8.8.8.8."
        )
        assert iocs["ip_addresses"] == ["192.168.1.100", "8.8.8.8"]

    def test_deduplicates_ips_preserving_order(self, agent: AutoPilotAgent) -> None:
        iocs = agent.extract_iocs("from 10.0.0.5, then 10.0.0.5 again, then 10.0.0.6")
        assert iocs["ip_addresses"] == ["10.0.0.5", "10.0.0.6"]

    def test_does_not_match_invalid_ip_octets(self, agent: AutoPilotAgent) -> None:
        """999.1.1.1 is not an address; the octet pattern must reject it."""
        iocs = agent.extract_iocs("src=999.1.1.1 dst=10.0.0.1")
        assert "999.1.1.1" not in iocs["ip_addresses"]
        assert iocs["ip_addresses"] == ["10.0.0.1"]

    def test_extracts_usernames(self, agent: AutoPilotAgent) -> None:
        iocs = agent.extract_iocs("user: admin from account: j.smith")
        assert set(iocs["usernames"]) == {"admin", "j.smith"}

    def test_username_key_is_case_insensitive(self, agent: AutoPilotAgent) -> None:
        iocs = agent.extract_iocs("USER: svc_backup")
        assert iocs["usernames"] == ["svc_backup"]

    def test_extracts_domains(self, agent: AutoPilotAgent) -> None:
        iocs = agent.extract_iocs("beacon to evil-c2.example.com and login.evil.org")
        assert set(iocs["domains"]) == {"evil-c2.example.com", "login.evil.org"}

    def test_ips_are_not_reported_as_domains(self, agent: AutoPilotAgent) -> None:
        """An IP matches the domain shape too; it must not appear in both."""
        iocs = agent.extract_iocs("connection to 203.0.113.42 and evil.com")
        assert "203.0.113.42" in iocs["ip_addresses"]
        assert "203.0.113.42" not in iocs["domains"]
        assert "evil.com" in iocs["domains"]

    def test_empty_input_yields_empty_lists(self, agent: AutoPilotAgent) -> None:
        iocs = agent.extract_iocs("nothing interesting here")
        assert iocs == {"ip_addresses": [], "usernames": [], "domains": []}


class TestThreatLevelMapping:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (100, "HIGHLY MALICIOUS"),
            (76, "HIGHLY MALICIOUS"),
            (75, "MALICIOUS"),
            (51, "MALICIOUS"),
            (50, "SUSPICIOUS"),
            (26, "SUSPICIOUS"),
            (25, "CLEAN"),
            (0, "CLEAN"),
        ],
    )
    def test_score_bands(self, score: int, expected: str) -> None:
        assert ThreatIntel("key")._derive_threat_level(score) == expected

    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("10.0.0.1", True),
            ("192.168.1.1", True),
            ("172.16.0.1", True),
            ("127.0.0.1", True),
            ("8.8.8.8", False),
            ("1.1.1.1", False),
        ],
    )
    def test_private_ip_detection(self, ip: str, expected: bool) -> None:
        assert ThreatIntel("key")._is_private_ip(ip) is expected

    def test_malformed_ip_is_not_private(self) -> None:
        """A non-address must not be silently treated as private."""
        assert ThreatIntel("key")._is_private_ip("not-an-ip") is False

    def test_safe_default_is_harmless(self) -> None:
        default = ThreatIntel._safe_default("1.2.3.4")
        assert default["abuse_confidence_score"] == 0
        assert default["total_reports"] == 0
        assert default["threat_level"] == "UNKNOWN"
        assert default["is_tor"] is False
        assert default["is_vpn"] is False


class TestKnowledgeBase:
    @pytest.fixture
    def kb(self, tmp_path: Path) -> KnowledgeBase:
        return KnowledgeBase(db_path=str(tmp_path / "kb.db"))

    def test_saves_and_returns_an_investigation(self, kb: KnowledgeBase) -> None:
        investigation_id = kb.save_investigation(
            "failed login from 10.0.0.1", {"ip_addresses": ["10.0.0.1"]},
            "malicious", "high", "summary",
        )
        assert investigation_id > 0
        similar = kb.get_similar_investigations("failed login from 10.0.0.1")
        assert len(similar) == 1
        assert similar[0]["verdict"] == "malicious"

    def test_similar_search_matches_on_overlapping_words(self, kb: KnowledgeBase) -> None:
        kb.save_investigation(
            "brute force login attempt against vpn", {}, "malicious", "high", "s",
        )
        similar = kb.get_similar_investigations("brute force login against vpn host")
        assert len(similar) == 1

    def test_unrelated_alert_does_not_match(self, kb: KnowledgeBase) -> None:
        kb.save_investigation("brute force login attempt", {}, "malicious", "high", "s")
        similar = kb.get_similar_investigations("disk space running low on host")
        assert similar == []

    def test_similar_search_respects_the_limit(self, kb: KnowledgeBase) -> None:
        for i in range(5):
            kb.save_investigation(f"brute force login {i}", {}, "malicious", "high", "s")
        assert len(kb.get_similar_investigations("brute force login", limit=2)) == 2

    def test_empty_description_returns_nothing(self, kb: KnowledgeBase) -> None:
        kb.save_investigation("brute force login", {}, "malicious", "high", "s")
        assert kb.get_similar_investigations("") == []

    def test_analyst_feedback_is_stored(self, kb: KnowledgeBase) -> None:
        investigation_id = kb.save_investigation(
            "some alert", {}, "suspicious", "medium", "s",
        )
        kb.add_analyst_feedback(investigation_id, "actually a false positive")
        row = kb.conn.execute(
            "SELECT analyst_feedback FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        assert row is not None
        assert "false positive" in row["analyst_feedback"]

    def test_analyst_feedback_can_correct_the_verdict(self, kb: KnowledgeBase) -> None:
        investigation_id = kb.save_investigation(
            "some alert", {}, "malicious", "high", "s",
        )
        kb.add_analyst_feedback(investigation_id, "benign", correct_verdict="false_positive")
        row = kb.conn.execute(
            "SELECT verdict FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
        assert row["verdict"] == "false_positive"

    def test_word_extraction_normalizes_case(self, kb: KnowledgeBase) -> None:
        assert kb._extract_words("Foo BAR foo") == {"foo", "bar"}
