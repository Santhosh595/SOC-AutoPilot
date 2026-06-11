import json
import os
import re

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from agent.knowledge_base import KnowledgeBase
from agent.llm_adapter import LLMAdapter
from agent.mcp_client import SplunkMCPClient
from agent.reporter import Reporter
from agent.notifier import Notifier
from agent.threat_intel import ThreatIntel


class AutoPilotAgent:
    """Coordinate IOC extraction, Splunk searches, AI analysis, and reporting."""

    def __init__(self, config: dict):
        """Initialize Splunk, LLM, knowledge base, threat intel, and console dependencies."""
        self.config = config
        self.console = Console()
        load_dotenv()
        self.splunk = self._safe_init_splunk(config)
        self.llm_adapter = self._safe_init_llm(config)
        self.knowledge_base = self._safe_init_knowledge_base()
        self.threat_intel = self._safe_init_threat_intel()
        self.notifier = self._safe_init_notifier(config)
        reports_dir = config.get("output", {}).get("reports_dir", "./reports")
        self.reporter = Reporter(reports_dir)

    def extract_iocs(self, alert_description: str) -> dict:
        """Extract IP addresses, usernames, and domains from an alert description."""
        ip_addresses = re.findall(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
            alert_description,
        )
        usernames = re.findall(
            r"\b(?:user|username|account):\s*([A-Za-z0-9._@\\-]+)",
            alert_description,
            re.IGNORECASE,
        )
        domains = re.findall(
            r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b",
            alert_description,
        )
        domains = [domain for domain in domains if domain not in ip_addresses]

        return {
            "ip_addresses": list(dict.fromkeys(ip_addresses)),
            "usernames": list(dict.fromkeys(usernames)),
            "domains": list(dict.fromkeys(domains)),
        }

    def investigate(self, alert_description: str) -> dict:
        """Run the full investigation workflow and return all collected findings."""
        self.console.print(Panel("SOC AutoPilot Investigating..."))

        iocs = {"ip_addresses": [], "usernames": [], "domains": []}
        similar_past_cases = []
        false_positive_matches = []
        log_results = []
        threat_enrichment = {}
        classification = self._safe_classification_default()
        report_markdown = ""
        detection_spl = ""
        investigation_id = None
        report_path = None
        spl_path = None

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True,
        ) as progress:
            task = progress.add_task("Starting investigation...", total=6)

            progress.update(task, description="[1/6] Extracting IOCs...")
            self.console.print("[1/6] Extracting IOCs...")
            try:
                iocs = self.extract_iocs(alert_description)
            except Exception as error:
                self.console.print(f"[red]IOC extraction failed: {error}[/red]")
            progress.advance(task)

            progress.update(
                task,
                description="[2/6] Checking knowledge base for similar past cases...",
            )
            self.console.print("[2/6] Checking knowledge base for similar past cases...")
            try:
                similar_past_cases = self.knowledge_base.get_similar_investigations(
                    alert_description
                )
                for ip_address in iocs.get("ip_addresses", []):
                    fp_match = self.knowledge_base.check_false_positive(
                        source_ip=ip_address
                    )
                    if fp_match.get("is_known_fp"):
                        fp_match["source_ip"] = ip_address
                        false_positive_matches.append(fp_match)
            except Exception as error:
                self.console.print(f"[red]Knowledge base lookup failed: {error}[/red]")
            progress.advance(task)

            progress.update(task, description="[3/6] Pulling logs from Splunk...")
            self.console.print("[3/6] Pulling logs from Splunk...")
            try:
                log_results.extend(self.splunk.get_alert_events(alert_description))
                for ip_address in iocs.get("ip_addresses", []):
                    log_results.extend(self.splunk.search_by_ip(ip_address))
                for username in iocs.get("usernames", []):
                    log_results.extend(self.splunk.search_by_user(username))
                log_results = self._deduplicate_events(log_results)[:100]
            except Exception as error:
                self.console.print(f"[red]Splunk log collection failed: {error}[/red]")
            progress.advance(task)

            progress.update(
                task,
                description="[3.5/6] Enriching IOCs with threat intelligence...",
            )
            self.console.print("[3.5/6] Enriching IOCs with threat intelligence...")
            try:
                threat_enrichment = self.threat_intel.enrich_investigation(iocs)
            except Exception as error:
                self.console.print(
                    f"[red]Threat intelligence enrichment failed: {error}[/red]"
                )

            progress.update(task, description="[4/6] Classifying threat with AI...")
            self.console.print("[4/6] Classifying threat with AI...")
            try:
                log_context = json.dumps(log_results, indent=2, default=str)
                if threat_enrichment:
                    log_context += (
                        "\n\n--- Threat Intelligence Enrichment ---\n"
                        + json.dumps(threat_enrichment, indent=2, default=str)
                    )
                classification = self._classify_threat(alert_description, log_context)
            except Exception as error:
                self.console.print(f"[red]AI classification failed: {error}[/red]")
            progress.advance(task)

            progress.update(task, description="[5/6] Generating investigation report...")
            self.console.print("[5/6] Generating investigation report...")
            investigation_data = {
                "alert_description": alert_description,
                "iocs": iocs,
                "threat_enrichment": threat_enrichment,
                "classification": classification,
                "log_summary": log_results[:20],
                "similar_past_cases": similar_past_cases,
                "false_positive_matches": false_positive_matches,
            }
            try:
                report_markdown = self._generate_report(investigation_data)
                detection_spl = self._generate_spl(alert_description)
            except Exception as error:
                self.console.print(f"[red]Report generation failed: {error}[/red]")

            if not report_markdown or report_markdown.startswith("LLM_ERROR:"):
                report_markdown = self._fallback_report(investigation_data)
            if detection_spl.startswith("LLM_ERROR:"):
                detection_spl = ""

            report_path = self.reporter.save_markdown_report(report_markdown)
            spl_path = self.reporter.save_spl_rule(detection_spl, alert_description) if detection_spl else None
            progress.advance(task)

            progress.update(task, description="[6/6] Saving to knowledge base...")
            self.console.print("[6/6] Saving to knowledge base...")
            try:
                investigation_id = self.knowledge_base.save_investigation(
                    alert_description=alert_description,
                    iocs=iocs,
                    verdict=classification.get("verdict", "NEEDS_REVIEW"),
                    severity=classification.get("severity", "MEDIUM"),
                    summary=classification.get("reasoning", ""),
                )
            except Exception as error:
                self.console.print(f"[red]Saving investigation failed: {error}[/red]")
            progress.advance(task)

        self.reporter.print_summary_table(
            classification, iocs, similar_past_cases, threat_enrichment
        )

        result = {
            "investigation_id": investigation_id,
            "alert_description": alert_description,
            "iocs": iocs,
            "threat_enrichment": threat_enrichment,
            "similar_past_cases": similar_past_cases,
            "false_positive_matches": false_positive_matches,
            "log_results": log_results,
            "classification": classification,
            "report": report_markdown,
            "detection_spl": detection_spl,
            "report_path": report_path,
            "spl_path": spl_path,
        }

        # Automatic notification for critical / high-severity threats
        try:
            self.notifier.notify(result)
        except Exception as error:
            self.console.print(f"[red]Notification failed: {error}[/red]")

        return result



    def get_feedback(
        self,
        investigation_id: int,
        feedback: str,
        correct_verdict: str = None,
    ):
        """Store analyst feedback and record false-positive patterns when applicable."""
        try:
            # Fetch IOCs before updating so we can record FP patterns
            ip_addresses = []
            if correct_verdict and correct_verdict.upper() == "FALSE_POSITIVE":
                try:
                    cursor = self.knowledge_base.conn.cursor()
                    cursor.execute(
                        "SELECT iocs FROM investigations WHERE id = ?",
                        (investigation_id,),
                    )
                    row = cursor.fetchone()
                    if row and row["iocs"]:
                        iocs = json.loads(row["iocs"])
                        ip_addresses = iocs.get("ip_addresses", [])
                except Exception as error:
                    self.console.print(
                        f"[yellow]Could not load IOCs for FP pattern: {error}[/yellow]"
                    )

            self.knowledge_base.add_analyst_feedback(
                investigation_id,
                feedback,
                correct_verdict,
            )

            # Record each source IP as a known false-positive pattern
            for ip_address in ip_addresses:
                try:
                    self.knowledge_base.add_false_positive_pattern(
                        pattern=feedback,
                        source_ip=ip_address,
                        alert_type="analyst_confirmed",
                    )
                except Exception as error:
                    self.console.print(
                        f"[yellow]Could not save FP pattern for {ip_address}: {error}[/yellow]"
                    )

            self.console.print("[green]Analyst feedback saved successfully[/green]")
            if ip_addresses:
                self.console.print(
                    f"[green]Recorded {len(ip_addresses)} IP(s) as false-positive patterns[/green]"
                )
        except Exception as error:
            self.console.print(f"[red]Failed to save analyst feedback: {error}[/red]")

    def _safe_init_splunk(self, config):
        """Initialize Splunk client without allowing startup failures to crash."""
        try:
            return SplunkMCPClient(config)
        except Exception as error:
            self.console.print(f"[red]Splunk client initialization failed: {error}[/red]")
            return _NullSplunkClient()

    def _safe_init_llm(self, config):
        """Initialize LLM adapter without allowing startup failures to crash."""
        try:
            return LLMAdapter(config)
        except Exception as error:
            self.console.print(f"[red]LLM initialization failed: {error}[/red]")
            return None

    def _safe_init_knowledge_base(self):
        """Initialize the knowledge base without allowing startup failures to crash."""
        try:
            return KnowledgeBase()
        except Exception as error:
            self.console.print(f"[red]Knowledge base initialization failed: {error}[/red]")
            return _NullKnowledgeBase()

    def _safe_init_threat_intel(self):
        """Initialize ThreatIntel with the AbuseIPDB key, or return a null fallback."""
        try:
            api_key = os.getenv("ABUSEIPDB_API_KEY", "")
            if not api_key:
                self.console.print(
                    "[yellow]ABUSEIPDB_API_KEY not set — threat intel disabled[/yellow]"
                )
                return _NullThreatIntel()
            return ThreatIntel(api_key)
        except Exception as error:
            self.console.print(
                f"[red]Threat intel initialization failed: {error}[/red]"
            )
            return _NullThreatIntel()

    def _safe_init_notifier(self, config):
        """Initialize the Notifier, or return a no-op fallback."""
        try:
            return Notifier(config)
        except Exception as error:
            self.console.print(
                f"[red]Notifier initialization failed: {error}[/red]"
            )
            return _NullNotifier()

    def _classify_threat(self, alert_description, log_context):
        """Classify a threat with the LLM or return a safe default."""
        if self.llm_adapter is None:
            return self._safe_classification_default()
        result = self.llm_adapter.classify_threat(alert_description, log_context)
        if not isinstance(result, dict):
            return self._safe_classification_default()
        return result

    def _generate_report(self, investigation_data):
        """Generate an AI report or return a fallback report."""
        if self.llm_adapter is None:
            return self._fallback_report(investigation_data)
        return self.llm_adapter.generate_report(investigation_data)

    def _generate_spl(self, alert_description):
        """Generate an SPL detection rule or return an empty string."""
        if self.llm_adapter is None:
            return ""
        return self.llm_adapter.generate_spl(alert_description)

    def _deduplicate_events(self, events):
        """Deduplicate Splunk events by stable JSON representation."""
        seen = set()
        deduplicated = []
        for event in events:
            key = json.dumps(event, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                deduplicated.append(event)
        return deduplicated

    def _fallback_report(self, investigation_data):
        """Create a local markdown report when AI report generation is unavailable."""
        classification = investigation_data.get("classification", {})
        return (
            "## Executive Summary\n"
            f"Investigation created for alert: {investigation_data.get('alert_description', '')}\n\n"
            "## Timeline\n"
            "No timeline was generated automatically.\n\n"
            "## Findings\n"
            f"IOCs: {json.dumps(investigation_data.get('iocs', {}), indent=2)}\n\n"
            "## Verdict & Severity\n"
            f"Verdict: {classification.get('verdict', 'NEEDS_REVIEW')}\n\n"
            f"Severity: {classification.get('severity', 'MEDIUM')}\n\n"
            "## Recommended Actions\n"
            f"{classification.get('recommended_action', 'Escalate to an analyst for manual review.')}\n\n"
            "## Detection Rule (SPL)\n"
            "No SPL rule was generated automatically.\n"
        )

    def _safe_classification_default(self):
        """Return a safe classification when AI analysis is unavailable."""
        return {
            "verdict": "NEEDS_REVIEW",
            "severity": "MEDIUM",
            "confidence": 0.0,
            "threat_type": "Unknown",
            "reasoning": "Automated classification was unavailable.",
            "recommended_action": "Escalate to an analyst for manual review.",
        }


class _NullSplunkClient:
    """Safe no-op Splunk client used when Splunk initialization fails."""

    def get_alert_events(self, alert_keyword: str, time_range="-24h") -> list:
        """Return no alert events."""
        return []

    def search_by_ip(self, ip_address: str, time_range="-24h") -> list:
        """Return no IP events."""
        return []

    def search_by_user(self, username: str, time_range="-24h") -> list:
        """Return no user events."""
        return []


class _NullKnowledgeBase:
    """Safe no-op knowledge base used when SQLite initialization fails."""

    def get_similar_investigations(self, alert_description, limit=5) -> list:
        """Return no similar investigations."""
        return []

    def check_false_positive(self, source_ip=None, alert_type=None) -> dict:
        """Return no false-positive match."""
        return {"is_known_fp": False, "count": 0, "pattern": None}

    def save_investigation(self, alert_description, iocs, verdict, severity, summary) -> int:
        """Return a null investigation ID."""
        return None

    def add_analyst_feedback(self, investigation_id, feedback, correct_verdict=None):
        """Ignore analyst feedback."""
        return None


class _NullThreatIntel:
    """Safe no-op threat intel used when AbuseIPDB is unavailable."""

    def check_ip(self, ip_address: str) -> dict:
        """Return a safe default for any IP."""
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

    def enrich_investigation(self, iocs: dict) -> dict:
        """Return empty enrichment."""
        return {}

    def format_enrichment_summary(self, enrichment: dict) -> str:
        """Return placeholder text."""
        return "_Threat intelligence unavailable._"


class _NullNotifier:
    """Safe no-op notifier used when notification setup fails."""

    def notify(self, investigation_result: dict) -> None:
        """Silently skip notification."""
        return None
