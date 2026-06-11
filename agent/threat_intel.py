"""
Threat Intelligence Enrichment — AbuseIPDB integration.

Enriches suspicious IP addresses found during SOC investigations
with reputation data from AbuseIPDB (free tier, no credit card).
"""

import ipaddress

import requests
from rich.console import Console

console = Console()


class ThreatIntel:
    """Query AbuseIPDB to enrich IOC IP addresses with threat reputation data."""

    # Threat-level boundaries derived from AbuseIPDB confidence scores.
    _THREAT_THRESHOLDS = [
        (76, "HIGHLY MALICIOUS"),
        (51, "MALICIOUS"),
        (26, "SUSPICIOUS"),
        (0, "CLEAN"),
    ]

    # Emoji indicators keyed by threat level for markdown output.
    _THREAT_EMOJI = {
        "HIGHLY MALICIOUS": "🔴",
        "MALICIOUS": "🟠",
        "SUSPICIOUS": "🟡",
        "CLEAN": "🟢",
        "UNKNOWN": "⚪",
    }

    # Maximum IPs to check per investigation (free-tier rate-limit safety).
    _MAX_IPS = 5

    def __init__(self, api_key: str):
        """Store AbuseIPDB credentials and prepare HTTP headers.

        Args:
            api_key: AbuseIPDB v2 API key (free at abuseipdb.com/register).
        """
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {"Key": api_key, "Accept": "application/json"}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_ip(self, ip_address: str) -> dict:
        """Look up a single IP address against AbuseIPDB.

        Returns a normalised dict with reputation fields.  If the API call
        fails, the IP is private/reserved, or any other error occurs, a
        safe default dict is returned so callers never need to handle
        exceptions.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            dict with keys: ip, abuse_confidence_score, total_reports,
            country_code, isp, usage_type, is_tor, is_vpn, last_reported,
            threat_level.
        """
        try:
            # Skip private / reserved ranges — AbuseIPDB rejects them.
            if self._is_private_ip(ip_address):
                console.print(
                    f"[dim]  ↳ {ip_address} is private/reserved — skipped[/dim]"
                )
                return self._safe_default(ip_address)

            response = requests.get(
                f"{self.base_url}/check",
                headers=self.headers,
                params={
                    "ipAddress": ip_address,
                    "maxAgeInDays": 90,
                    "verbose": True,
                },
                timeout=15,
            )
            response.raise_for_status()

            data = response.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            usage_type = str(data.get("usageType", "") or "")

            result = {
                "ip": ip_address,
                "abuse_confidence_score": score,
                "total_reports": int(data.get("totalReports", 0)),
                "country_code": str(data.get("countryCode", "") or ""),
                "isp": str(data.get("isp", "") or ""),
                "usage_type": usage_type,
                "is_tor": bool(data.get("isTor", False)),
                "is_vpn": "VPN" in usage_type.upper(),
                "last_reported": str(data.get("lastReportedAt", "") or "N/A"),
                "threat_level": self._derive_threat_level(score),
            }

            emoji = self._THREAT_EMOJI.get(result["threat_level"], "⚪")
            console.print(
                f"  {emoji} {ip_address} — "
                f"score {score}/100, "
                f"{result['total_reports']} report(s), "
                f"{result['threat_level']}"
            )
            return result

        except requests.exceptions.RequestException as error:
            console.print(
                f"[red]  ✗ AbuseIPDB request failed for {ip_address}: {error}[/red]"
            )
            return self._safe_default(ip_address)
        except Exception as error:
            console.print(
                f"[red]  ✗ Unexpected error checking {ip_address}: {error}[/red]"
            )
            return self._safe_default(ip_address)

    def enrich_investigation(self, iocs: dict) -> dict:
        """Enrich all IP addresses extracted from an alert.

        Checks up to ``_MAX_IPS`` addresses to stay within the AbuseIPDB
        free-tier rate limit.

        Args:
            iocs: Dict with keys ``ip_addresses``, ``usernames``,
                  ``domains`` (as produced by ``AutoPilotAgent.extract_iocs``).

        Returns:
            Dict mapping each checked IP string to its ``check_ip`` result.
        """
        ip_list = iocs.get("ip_addresses", [])
        if not ip_list:
            console.print("[dim]  No IP addresses to enrich.[/dim]")
            return {}

        ips_to_check = ip_list[: self._MAX_IPS]
        if len(ip_list) > self._MAX_IPS:
            console.print(
                f"[yellow]  Limiting enrichment to first {self._MAX_IPS} "
                f"of {len(ip_list)} IPs[/yellow]"
            )

        enrichment: dict = {}
        for ip in ips_to_check:
            enrichment[ip] = self.check_ip(ip)

        return enrichment

    def format_enrichment_summary(self, enrichment: dict) -> str:
        """Render enrichment results as a readable markdown string.

        Args:
            enrichment: Dict returned by ``enrich_investigation()``.

        Returns:
            Formatted markdown text ready for inclusion in reports.
        """
        if not enrichment:
            return "_No threat intelligence data available._"

        lines = ["### Threat Intelligence Enrichment\n"]

        for ip, info in enrichment.items():
            threat = info.get("threat_level", "UNKNOWN")
            emoji = self._THREAT_EMOJI.get(threat, "⚪")
            score = info.get("abuse_confidence_score", 0)

            lines.append(f"**{emoji} {ip}** — {threat} (score {score}/100)")
            lines.append(f"- ISP: {info.get('isp', 'N/A')}")
            lines.append(f"- Country: {info.get('country_code', 'N/A')}")
            lines.append(f"- Usage: {info.get('usage_type', 'N/A')}")
            lines.append(f"- Reports: {info.get('total_reports', 0)}")
            lines.append(f"- Tor: {'Yes' if info.get('is_tor') else 'No'}")
            lines.append(f"- VPN: {'Yes' if info.get('is_vpn') else 'No'}")
            lines.append(
                f"- Last Reported: {info.get('last_reported', 'N/A')}"
            )
            lines.append("")  # blank line between IPs

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _derive_threat_level(self, score: int) -> str:
        """Map an AbuseIPDB confidence score to a human-readable threat level."""
        for threshold, label in self._THREAT_THRESHOLDS:
            if score >= threshold:
                return label
        return "CLEAN"

    def _is_private_ip(self, ip_string: str) -> bool:
        """Return True if the IP is private, loopback, or reserved."""
        try:
            addr = ipaddress.ip_address(ip_string)
            return addr.is_private or addr.is_loopback or addr.is_reserved
        except ValueError:
            return False

    @staticmethod
    def _safe_default(ip_address: str) -> dict:
        """Return a harmless default when enrichment is unavailable."""
        return {
            "ip": ip_address,
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "country_code": "",
            "isp": "",
            "usage_type": "",
            "is_tor": False,
            "is_vpn": False,
            "last_reported": "N/A",
            "threat_level": "UNKNOWN",
        }
