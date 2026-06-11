"""
Notifier — Automatic Slack and Email alerts for critical investigations.

Sends notifications when SOC AutoPilot detects a MALICIOUS threat with
CRITICAL or HIGH severity.  Both channels are optional — each is only
activated when the matching configuration values are present.
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests
from rich.console import Console

console = Console()


class Notifier:
    """Deliver investigation alerts over Slack webhooks and/or SMTP email."""

    # Only fire notifications for these combinations.
    _NOTIFY_VERDICTS = {"MALICIOUS"}
    _NOTIFY_SEVERITIES = {"CRITICAL", "HIGH"}

    def __init__(self, config: dict):
        """Read notification settings from the config dict.

        Args:
            config: Full application config.  The ``notifications`` key is
                    optional — if absent, all channels are silently disabled.
        """
        notif = config.get("notifications", {}) or {}

        # Slack
        self.slack_webhook = (notif.get("slack_webhook") or "").strip() or None

        # Email / SMTP
        self.email_to = (notif.get("email_to") or "").strip() or None
        self.email_from = (notif.get("email_from") or "").strip() or None
        self.smtp_host = notif.get("smtp_host", "smtp.gmail.com")
        self.smtp_port = int(notif.get("smtp_port", 587))
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")

        # Derived flags
        self.slack_enabled = self.slack_webhook is not None
        self.email_enabled = (
            self.email_to is not None
            and self.email_from is not None
            and bool(self.smtp_password)
        )

        if self.slack_enabled:
            console.print("[dim]Notifier: Slack channel enabled[/dim]")
        if self.email_enabled:
            console.print("[dim]Notifier: Email channel enabled[/dim]")
        if not self.slack_enabled and not self.email_enabled:
            console.print(
                "[dim]Notifier: No channels configured — notifications disabled[/dim]"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def notify(self, investigation_result: dict) -> None:
        """Evaluate an investigation result and send alerts if warranted.

        Notifications are sent only when the verdict is MALICIOUS **and**
        the severity is CRITICAL or HIGH.  The method never raises — all
        failures are caught and printed via Rich.

        Args:
            investigation_result: The dict returned by
                ``AutoPilotAgent.investigate()``.
        """
        try:
            classification = investigation_result.get("classification", {})
            verdict = str(classification.get("verdict", "")).upper()
            severity = str(classification.get("severity", "")).upper()

            if verdict not in self._NOTIFY_VERDICTS or severity not in self._NOTIFY_SEVERITIES:
                console.print(
                    "[green][NOTIFIER] No notification needed (low severity)[/green]"
                )
                return

            sent = False

            if self.slack_enabled:
                self.send_slack(investigation_result)
                sent = True

            if self.email_enabled:
                self.send_email(investigation_result)
                sent = True

            if sent:
                console.print("[bold red][NOTIFIER] Alert sent[/bold red]")
            else:
                console.print(
                    "[yellow][NOTIFIER] Threshold met but no channels configured[/yellow]"
                )
        except Exception as error:
            console.print(f"[red][NOTIFIER] Unexpected error: {error}[/red]")

    # ------------------------------------------------------------------
    # Slack
    # ------------------------------------------------------------------

    def send_slack(self, investigation_result: dict) -> None:
        """Post an alert to the configured Slack webhook using Block Kit.

        Args:
            investigation_result: Full investigation result dict.
        """
        try:
            classification = investigation_result.get("classification", {})
            alert_desc = str(
                investigation_result.get("alert_description", "N/A")
            )[:100]

            confidence_pct = self._confidence_pct(classification)

            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚨 SOC AutoPilot Critical Alert",
                        "emoji": True,
                    },
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"*Verdict:* {classification.get('verdict', 'N/A')} "
                                f"| *Severity:* {classification.get('severity', 'N/A')}"
                            ),
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Threat Type:* {classification.get('threat_type', 'Unknown')}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Confidence:* {confidence_pct}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Alert:* {alert_desc}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"*Recommended Action:* "
                                f"{classification.get('recommended_action', 'N/A')}"
                            ),
                        },
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"*Report saved at:* "
                                f"`{investigation_result.get('report_path', 'N/A')}`"
                            ),
                        },
                    ],
                },
                {"type": "divider"},
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "SOC AutoPilot | Splunk Agentic Ops",
                        }
                    ],
                },
            ]

            payload = {"blocks": blocks}
            response = requests.post(
                self.slack_webhook,
                json=payload,
                timeout=10,
            )
            response.raise_for_status()
            console.print("[green]  ✓ Slack notification sent[/green]")

        except requests.exceptions.RequestException as error:
            console.print(f"[red]  ✗ Slack notification failed: {error}[/red]")
        except Exception as error:
            console.print(
                f"[red]  ✗ Unexpected Slack error: {error}[/red]"
            )

    # ------------------------------------------------------------------
    # Email
    # ------------------------------------------------------------------

    def send_email(self, investigation_result: dict) -> None:
        """Send an HTML alert email via SMTP with TLS.

        Args:
            investigation_result: Full investigation result dict.
        """
        try:
            classification = investigation_result.get("classification", {})
            threat_type = classification.get("threat_type", "Unknown")
            alert_desc = str(
                investigation_result.get("alert_description", "N/A")
            )[:100]

            confidence_pct = self._confidence_pct(classification)

            subject = f"🚨 [CRITICAL] SOC AutoPilot Alert: {threat_type}"

            html_body = f"""\
<html>
<body style="font-family: Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 24px;">
  <div style="max-width: 600px; margin: auto; background: #16213e; border-radius: 12px; padding: 24px; border: 1px solid #0f3460;">
    <h1 style="color: #e94560; margin-top: 0;">🚨 SOC AutoPilot Critical Alert</h1>
    <hr style="border-color: #0f3460;">
    <table style="width: 100%; border-collapse: collapse;">
      <tr>
        <td style="padding: 8px 0; color: #a0a0a0; width: 160px;">Verdict</td>
        <td style="padding: 8px 0; color: #e94560; font-weight: bold;">
            {classification.get("verdict", "N/A")}
        </td>
      </tr>
      <tr>
        <td style="padding: 8px 0; color: #a0a0a0;">Severity</td>
        <td style="padding: 8px 0; color: #ff6b6b; font-weight: bold;">
            {classification.get("severity", "N/A")}
        </td>
      </tr>
      <tr>
        <td style="padding: 8px 0; color: #a0a0a0;">Threat Type</td>
        <td style="padding: 8px 0;">{threat_type}</td>
      </tr>
      <tr>
        <td style="padding: 8px 0; color: #a0a0a0;">Confidence</td>
        <td style="padding: 8px 0;">{confidence_pct}</td>
      </tr>
      <tr>
        <td style="padding: 8px 0; color: #a0a0a0;">Alert</td>
        <td style="padding: 8px 0;">{alert_desc}</td>
      </tr>
      <tr>
        <td style="padding: 8px 0; color: #a0a0a0;">Recommended Action</td>
        <td style="padding: 8px 0;">
            {classification.get("recommended_action", "N/A")}
        </td>
      </tr>
      <tr>
        <td style="padding: 8px 0; color: #a0a0a0;">Report Path</td>
        <td style="padding: 8px 0; font-family: monospace;">
            {investigation_result.get("report_path", "N/A")}
        </td>
      </tr>
    </table>
    <hr style="border-color: #0f3460;">
    <p style="color: #666; font-size: 12px; margin-bottom: 0;">
        SOC AutoPilot | Splunk Agentic Ops
    </p>
  </div>
</body>
</html>"""

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.email_from
            msg["To"] = self.email_to
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                server.starttls()
                server.login(self.email_from, self.smtp_password)
                server.sendmail(self.email_from, [self.email_to], msg.as_string())

            console.print("[green]  ✓ Email notification sent[/green]")

        except smtplib.SMTPException as error:
            console.print(f"[red]  ✗ Email notification failed: {error}[/red]")
        except Exception as error:
            console.print(
                f"[red]  ✗ Unexpected email error: {error}[/red]"
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _confidence_pct(classification: dict) -> str:
        """Convert the confidence float to a percentage string."""
        try:
            return f"{float(classification.get('confidence', 0)) * 100:.0f}%"
        except (TypeError, ValueError):
            return "0%"
