import json
import os
import re

from dotenv import load_dotenv
from google import genai


class LLMAdapter:
    """Provide a single interface for Gemini-powered SOC analysis tasks."""

    def __init__(self, config: dict):
        """Load Gemini configuration, initialize the API client."""
        load_dotenv()
        self.config = config
        self.demo_mode = config.get("demo_mode", False)
        self.provider = config.get("ai", {}).get("provider", "gemini")
        self.model_name = config.get("ai", {}).get("gemini_model", "gemini-2.0-flash")
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.client = None

        if self.demo_mode:
            return

        if self.provider != "gemini":
            raise ValueError(f"Unsupported AI provider: {self.provider}")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set")

        self.client = genai.Client(api_key=self.api_key)

    def analyze(self, system_prompt: str, user_prompt: str) -> str:
        """Send a prompt to Gemini and return the plain text response."""
        if self.client is None:
            return ""
        try:
            prompt = f"{system_prompt.strip()}\n\n{user_prompt.strip()}"
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
            )
            return response.text.strip() if response.text else ""
        except Exception as error:
            return "LLM_ERROR: " + str(error)

    def classify_threat(self, alert_text: str, log_context: str) -> dict:
        """Classify an alert using Gemini and return a normalized threat dictionary."""
        system_prompt = (
            "You are an expert SOC analyst. Analyze alerts and supporting logs with "
            "careful security reasoning. Return ONLY a JSON object with keys: "
            "verdict, severity, confidence, threat_type, reasoning, recommended_action. "
            "verdict must be one of MALICIOUS, FALSE_POSITIVE, NEEDS_REVIEW. "
            "severity must be one of CRITICAL, HIGH, MEDIUM, LOW. "
            "confidence must be a float from 0.0 to 1.0. "
            "reasoning must be 2-3 sentences."
        )
        user_prompt = (
            "Classify this security alert.\n\n"
            f"Alert:\n{alert_text}\n\n"
            f"Log context:\n{log_context}"
        )

        response_text = self.analyze(system_prompt, user_prompt)
        try:
            parsed = json.loads(self._extract_json(response_text))
            return {
                "verdict": parsed.get("verdict", "NEEDS_REVIEW"),
                "severity": parsed.get("severity", "MEDIUM"),
                "confidence": float(parsed.get("confidence", 0.0)),
                "threat_type": parsed.get("threat_type", "Unknown"),
                "reasoning": parsed.get("reasoning", "Unable to parse model reasoning."),
                "recommended_action": parsed.get(
                    "recommended_action",
                    "Escalate to an analyst for manual review.",
                ),
            }
        except Exception:
            return self._safe_classification_default()

    def generate_spl(self, description: str) -> str:
        """Generate a single Splunk SPL query and strip markdown code fences."""
        system_prompt = (
            "You are a Splunk SPL expert, return only the SPL query with no explanation."
        )
        user_prompt = f"Generate a Splunk SPL query for this detection:\n{description}"
        response_text = self.analyze(system_prompt, user_prompt)
        return self._strip_code_fences(response_text).strip()

    def generate_report(self, investigation_data: dict) -> str:
        """Generate a structured markdown incident report from investigation data."""
        system_prompt = (
            "You are a senior SOC analyst. Write concise, structured markdown incident "
            "reports for security investigations."
        )
        user_prompt = (
            "Use the following investigation data as JSON context and write a markdown "
            "incident report with these sections:\n"
            "## Executive Summary\n"
            "## Timeline\n"
            "## Findings\n"
            "## Verdict & Severity\n"
            "## Recommended Actions\n"
            "## Detection Rule (SPL)\n\n"
            f"{json.dumps(investigation_data, indent=2)}"
        )
        return self.analyze(system_prompt, user_prompt)

    def _extract_json(self, text: str) -> str:
        """Extract a JSON object from raw model text."""
        stripped = self._strip_code_fences(text).strip()
        match = re.search(r"\{.*\}", stripped, re.DOTALL)
        if match:
            return match.group(0)
        return stripped

    def _strip_code_fences(self, text: str) -> str:
        """Remove markdown code fences from model output."""
        stripped = text.strip()
        if stripped.startswith("```"):
            stripped = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", stripped)
            stripped = re.sub(r"\s*```$", "", stripped)
        return stripped

    def _safe_classification_default(self) -> dict:
        """Return a safe default classification when model output cannot be parsed."""
        return {
            "verdict": "NEEDS_REVIEW",
            "severity": "MEDIUM",
            "confidence": 0.0,
            "threat_type": "Unknown",
            "reasoning": "The model response could not be parsed as valid JSON.",
            "recommended_action": "Escalate to an analyst for manual review.",
        }
