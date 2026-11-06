"""
Splunk MCP Client — REST API wrapper using basic auth (no tokens needed).
Connects to Splunk using username/password instead of bearer tokens.
Handles SSL warnings for self-signed certificates.
"""

import json
import os
import warnings
from concurrent.futures import ThreadPoolExecutor

import requests
from requests.auth import HTTPBasicAuth
from rich.console import Console

console = Console()


class SplunkMCPClient:
    """
    REST API client for Splunk. Uses basic auth (username/password).
    No tokens needed. Works with local Splunk instances.
    """

    def __init__(self, config: dict):
        """
        Initialize Splunk connection from config.

        Args:
            config (dict): Configuration dict with structure:
                config["splunk"]["host"] = "localhost"
                config["splunk"]["port"] = 8000
                config["splunk"]["username"] = "admin"
                config["splunk"]["password"] = "your_password"
                config["splunk"]["verify_ssl"] = True
        """
        self.host = config.get("splunk", {}).get("host", "localhost")
        self.port = config.get("splunk", {}).get("port", 8000)
        self.username = config.get("splunk", {}).get("username", "admin")
        self.password = config.get("splunk", {}).get("password", "") or os.getenv("SPLUNK_PASSWORD", "")
        self.verify_ssl = config.get("splunk", {}).get("verify_ssl", True)
        # Parallel Splunk searches: up to this many run at once. Splunk
        # oneshot jobs are network-bound, so overlapping them directly
        # shortens investigations when many IOCs are searched.
        self.max_workers = max(
            1, int(config.get("splunk", {}).get("max_workers", 4))
        )

        self.base_url = f"https://{self.host}:{self.port}"
        self.auth = HTTPBasicAuth(self.username, self.password)
        self.headers = {"Content-Type": "application/json"}

        if not self.verify_ssl:
            # Opt-in only: the caller explicitly turned verification OFF.
            # Downgrade the warning to a printed notice instead of hiding it.
            warnings.filterwarnings("ignore", message=".*InsecureRequestWarning.*")
            console.print(
                "[yellow]SSL verification disabled — Splunk connection is not "
                "verified. Set splunk.verify_ssl: true to restore checks.[/yellow]"
            )

    def run_search(
        self, spl_query: str, earliest="-24h", latest="now", max_results=100
    ) -> list:
        """
        Execute a Splunk search query.

        Args:
            spl_query (str): SPL search string
            earliest (str): Earliest time range (default: -24h)
            latest (str): Latest time range (default: now)
            max_results (int): Maximum results to return (default: 100)

        Returns:
            list: List of result dictionaries from Splunk, or empty list if error
        """
        search_params = {
            "search": spl_query,
            "output_mode": "json",
            "exec_mode": "oneshot",
            "earliest_time": earliest,
            "latest_time": latest,
            "count": max_results,
        }
        return self._run_one(search_params)

    def run_searches(self, search_params_list: list) -> list:
        """Run several searches concurrently and flatten the results.

        Results come back in submission order; empty results (a failed
        search) are dropped and duplicates removed.
        """
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            results = list(pool.map(self._run_one, search_params_list))
        flat = []
        for batch in results:
            flat.extend(batch)
        return self._dedupe(flat)

    def _run_one(self, search_params: dict) -> list:
        """Execute one Splunk oneshot search (a single pool worker)."""
        try:
            response = requests.post(
                f"{self.base_url}/services/search/jobs",
                data=search_params,
                auth=self.auth,
                verify=self.verify_ssl,
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])
                return results
            else:
                console.print(
                    f"[red]Search failed: HTTP {response.status_code}[/red]"
                )
                return []

        except requests.exceptions.RequestException as e:
            console.print(f"[red]Search error: {str(e)}[/red]")
            return []
        except Exception as e:
            console.print(f"[red]Unexpected error in run_search: {str(e)}[/red]")
            return []

    @staticmethod
    def _dedupe(events: list) -> list:
        """Deduplicate events by stable JSON representation, keep order."""
        seen = set()
        unique = []
        for event in events:
            key = json.dumps(event, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                unique.append(event)
        return unique

    def get_alert_events(self, alert_keyword: str, time_range="-24h") -> list:
        """
        Search for alert events by keyword.

        Args:
            alert_keyword (str): Keyword to search for in alerts
            time_range (str): Time range (default: -24h)

        Returns:
            list: List of matching alert events
        """
        try:
            spl = f'search index=* earliest={time_range} | search "{alert_keyword}" | head 50'
            results = self.run_search(spl, earliest=time_range, max_results=50)
            return results
        except Exception as e:
            console.print(f"[red]Error in get_alert_events: {str(e)}[/red]")
            return []

    def search_by_ip(self, ip_address: str, time_range="-24h") -> list:
        """
        Search for all events related to an IP address.

        Args:
            ip_address (str): IP address to search for
            time_range (str): Time range (default: -24h)

        Returns:
            list: List of events involving this IP
        """
        try:
            spl = f'search index=* earliest={time_range} "{ip_address}" | head 100'
            results = self.run_search(spl, earliest=time_range, max_results=100)
            return results
        except Exception as e:
            console.print(f"[red]Error in search_by_ip: {str(e)}[/red]")
            return []

    def search_by_user(self, username: str, time_range="-24h") -> list:
        """
        Search for all events related to a user.

        Args:
            username (str): Username to search for
            time_range (str): Time range (default: -24h)

        Returns:
            list: List of events involving this user
        """
        try:
            spl = f'search index=* earliest={time_range} (user="{username}" OR User="{username}") | head 100'
            results = self.run_search(spl, earliest=time_range, max_results=100)
            return results
        except Exception as e:
            console.print(f"[red]Error in search_by_user: {str(e)}[/red]")
            return []

    def get_failed_logins(self, time_range="-1h") -> list:
        """
        Search for failed login attempts.

        Args:
            time_range (str): Time range (default: -1h)

        Returns:
            list: List of failed login events
        """
        try:
            spl = f'search index=* earliest={time_range} (EventCode=4625 OR "failed login" OR "authentication failure") | stats count by src_ip, user, _time | sort -count | head 20'
            results = self.run_search(spl, earliest=time_range, max_results=20)
            return results
        except Exception as e:
            console.print(f"[red]Error in get_failed_logins: {str(e)}[/red]")
            return []

    def test_connection(self) -> bool:
        """
        Test the connection to Splunk.

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # Try a simple search to verify auth and connection
            search_params = {
                "search": "search index=_internal | head 1",
                "output_mode": "json",
                "exec_mode": "oneshot",
                "count": 1,
            }

            response = requests.post(
                f"{self.base_url}/services/search/jobs",
                data=search_params,
                auth=self.auth,
                verify=self.verify_ssl,
                timeout=10,
            )

            if response.status_code == 200:
                console.print(
                    "[green]✓ Splunk connection successful[/green]"
                )
                return True
            else:
                console.print(
                    f"[red]✗ Splunk connection failed: HTTP {response.status_code}[/red]"
                )
                console.print(
                    "[yellow]  Check your username and password in .env[/yellow]"
                )
                return False

        except requests.exceptions.ConnectionError:
            console.print(
                "[red]✗ Cannot connect to Splunk[/red]"
            )
            console.print(
                f"[yellow]  Is Splunk running at {self.base_url}?[/yellow]"
            )
            return False
        except Exception as e:
            console.print(f"[red]✗ Connection test error: {str(e)}[/red]")
            return False