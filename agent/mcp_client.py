import json
import os
from datetime import datetime, timedelta

import requests
import urllib3
from rich.console import Console


class SplunkMCPClient:
    """Connect to Splunk REST endpoints used by the SOC AutoPilot agent."""

    def __init__(self, config: dict):
        """Initialize Splunk connection settings from project configuration."""
        splunk_config = config.get("splunk", {})
        self.demo_mode = config.get("demo_mode", False)
        self.host = splunk_config.get("host", "localhost")
        self.port = splunk_config.get("port", 8000)
        self.token = splunk_config.get("token", "")
        self.verify_ssl = splunk_config.get("verify_ssl", False)
        self.base_url = f"https://{self.host}:{self.port}"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        self.console = Console()
        self.sample_alerts = self._load_sample_alerts()

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def run_search(
        self,
        spl_query: str,
        earliest="-24h",
        latest="now",
        max_results=100,
    ) -> list:
        """Run a Splunk oneshot search and return result dictionaries."""
        if self.demo_mode:
            return self._demo_search_results(spl_query, max_results)

        try:
            response = requests.post(
                f"{self.base_url}/services/search/jobs",
                headers=self.headers,
                params={
                    "search": spl_query,
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                    "earliest_time": earliest,
                    "latest_time": latest,
                    "count": max_results,
                },
                verify=self.verify_ssl,
                timeout=30,
            )
            response.raise_for_status()
            payload = response.json()
            return payload.get("results", []) or []
        except Exception as error:
            self.console.print(f"[red]Splunk search failed: {error}[/red]")
            return []

    def get_alert_events(self, alert_keyword: str, time_range="-24h") -> list:
        """Search recent Splunk events that contain an alert keyword."""
        if self.demo_mode:
            return self._demo_alert_events(alert_keyword)[:50]

        spl_query = f'search index=* earliest={time_range} | search "{alert_keyword}" | head 50'
        return self.run_search(spl_query)

    def search_by_ip(self, ip_address: str, time_range="-24h") -> list:
        """Search recent Splunk events for a specific IP address."""
        if self.demo_mode:
            return [
                event
                for event in self._demo_events()
                if ip_address in {event.get("src_ip"), event.get("dest_ip")}
            ][:100]

        spl_query = f'search index=* earliest={time_range} "{ip_address}" | head 100'
        return self.run_search(spl_query)

    def search_by_user(self, username: str, time_range="-24h") -> list:
        """Search recent Splunk events for a specific username."""
        if self.demo_mode:
            return [
                event
                for event in self._demo_events()
                if str(event.get("user", "")).lower() == username.lower()
            ][:100]

        spl_query = (
            f'search index=* earliest={time_range} '
            f'user="{username}" OR User="{username}" | head 100'
        )
        return self.run_search(spl_query)

    def get_failed_logins(self, time_range="-1h") -> list:
        """Search for failed login activity and return the top grouped results."""
        if self.demo_mode:
            return [
                event
                for event in self._demo_events()
                if event.get("EventCode") == 4625
            ][:20]

        spl_query = (
            f'search index=* earliest={time_range} '
            '(EventCode=4625 OR "failed login" OR "authentication failure") '
            "| stats count by src_ip, user, _time | sort -count | head 20"
        )
        return self.run_search(spl_query)

    def test_connection(self) -> bool:
        """Run a simple Splunk search and print whether the connection works."""
        if self.demo_mode:
            self.console.print("[green]Demo mode enabled. Splunk connection skipped.[/green]")
            return True

        try:
            response = requests.post(
                f"{self.base_url}/services/search/jobs",
                headers=self.headers,
                params={
                    "search": "search index=_internal | head 1",
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                },
                verify=self.verify_ssl,
                timeout=30,
            )
            response.raise_for_status()
            self.console.print("[green]Splunk connection successful[/green]")
            return True
        except Exception as error:
            self.console.print(f"[red]Splunk connection failed: {error}[/red]")
            return False

    def _load_sample_alerts(self) -> list:
        """Load local sample alert descriptions for demo mode."""
        sample_path = os.path.join("sample_data", "sample_alerts.json")
        try:
            with open(sample_path, "r", encoding="utf-8") as sample_file:
                return json.load(sample_file)
        except Exception:
            return []

    def _demo_search_results(self, spl_query: str, max_results=100) -> list:
        """Return fake Splunk results for a demo-mode SPL query."""
        query = spl_query.lower()
        events = self._demo_events()

        if "185.220.101.45" in query or "brute" in query or "4625" in query:
            return [event for event in events if event.get("scenario") == "Brute Force Attack"][
                :max_results
            ]
        if "powershell" in query or "4688" in query or "jsmith" in query:
            return [
                event
                for event in events
                if event.get("scenario") == "Suspicious PowerShell"
            ][:max_results]
        if "203.0.113.99" in query or "svc_backup" in query or "bytes_out" in query:
            return [
                event
                for event in events
                if event.get("scenario") == "Data Exfiltration Pattern"
            ][:max_results]
        return events[:max_results]

    def _demo_alert_events(self, alert_keyword: str) -> list:
        """Return demo events that best match a sample alert description."""
        alert_text = alert_keyword.lower()
        for sample_alert in self.sample_alerts:
            if self._shares_words(alert_text, sample_alert.lower()):
                return self._demo_search_results(sample_alert, 100)
        return self._demo_search_results(alert_keyword, 100)

    def _demo_events(self) -> list:
        """Build deterministic fake events for local demo investigations."""
        now = datetime.utcnow()
        events = []

        for index in range(50):
            events.append(
                {
                    "_time": (now - timedelta(minutes=120 - index * 2)).isoformat(),
                    "scenario": "Brute Force Attack",
                    "EventCode": 4625,
                    "action": "failure",
                    "src_ip": "185.220.101.45",
                    "user": "admin",
                    "host": "DC-01",
                    "signature": "An account failed to log on",
                }
            )
        events.append(
            {
                "_time": (now - timedelta(minutes=1)).isoformat(),
                "scenario": "Brute Force Attack",
                "EventCode": 4624,
                "action": "success",
                "src_ip": "185.220.101.45",
                "user": "admin",
                "host": "DC-01",
                "signature": "An account was successfully logged on",
            }
        )

        for index in range(5):
            events.append(
                {
                    "_time": (now - timedelta(minutes=45 - index * 4)).isoformat(),
                    "scenario": "Suspicious PowerShell",
                    "EventCode": 4688,
                    "user": "jsmith",
                    "host": "WORKSTATION-04",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
                }
            )

        for index in range(10):
            events.append(
                {
                    "_time": (now - timedelta(minutes=30 - index * 2)).isoformat(),
                    "scenario": "Data Exfiltration Pattern",
                    "action": "allowed",
                    "direction": "outbound",
                    "src_ip": "10.10.4.25",
                    "dest_ip": "203.0.113.99",
                    "user": "svc_backup",
                    "host": "BACKUP-SRV-01",
                    "bytes_out": 50000001 + index * 5000000,
                }
            )

        return events

    def _shares_words(self, left: str, right: str) -> bool:
        """Return whether two strings share any meaningful words."""
        left_words = {word for word in left.split() if len(word) > 3}
        right_words = {word for word in right.split() if len(word) > 3}
        return bool(left_words & right_words)
