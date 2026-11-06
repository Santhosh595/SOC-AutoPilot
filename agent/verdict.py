"""Investigator Verdict — the unique, explainable go/no-go gate.

The LLM classification alone can be wrong. The Verdict fuses four
independent signals into one confidence-scored decision:

  - LLM verdict + confidence (from agent.llm_adapter)
  - AbuseIPDB threat score (max abuse_confidence_score across IPs)
  - False-positive history (how often this IP was confirmed benign)
  - Log volume (how much corroborating Splunk evidence was found)
  - ATT&CK guess (keyword hint from the alert text, reasoned in-code)

The output is always a dict; callers never need exception handling.
"""

VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_FALSE_POSITIVE = "FALSE_POSITIVE"
VERDICT_NEEDS_REVIEW = "NEEDS_REVIEW"

# Signals -> score 0..1 (higher = more likely truly malicious)
HIGH_FP_COUNT = 3          # >= this many FP confirms on one IP: strong FP evidence
HIGH_THREAT_SCORE = 75     # AbuseIPDB >= 75: strong malicious evidence
MED_THREAT_SCORE = 50

# Thresholds for final decision
MALICIOUS_AT = 0.65
FALSE_POSITIVE_AT = 0.35


def _threat_score_of(enrichment: dict) -> float:
    """Max AbuseIPDB score across enriched IPs, as 0..1 (0 if none)."""
    best = 0
    for info in (enrichment or {}).values():
        try:
            best = max(best, int(info.get("abuse_confidence_score", 0)))
        except (TypeError, ValueError):
            continue
    return best / 100.0


def _fp_count_of(false_positive_matches: list) -> int:
    """Largest confirmed-FP count across known-pattern matches (0 if none)."""
    best = 0
    for match in false_positive_matches or []:
        try:
            best = max(best, int(match.get("count", 0)))
        except (TypeError, ValueError):
            continue
    return best


def _volume_score(log_results: list) -> float:
    """Log volume as 0..1 sanity score: 0 events -> 0, 20+ -> 1.0."""
    count = len(log_results or [])
    return min(1.0, count / 20.0)


def guess_attack_tactic(alert_description: str) -> tuple:
    """Keyword-hint at MITRE ATT&CK tactic. Pure function, testable.

    Returns (technique_id, tactic, confidence 0..1). 'T0000'/'Unknown'
    when the text matches nothing known — the guesser never invents a
    technique it did not see evidence for.
    """
    text = (alert_description or "").lower()
    rules = [
        (("brute force", "failed login", "authentication failure", "4625"),
         ("T1110", "Credential Access", 0.8)),
        (("powershell", "encodedcommand", "bypass", "execution bypass"),
         ("T1059.001", "Execution", 0.7)),
        (("mimikatz", "credential dumping", "lsass"),
         ("T1003.001", "Credential Access", 0.8)),
        (("ransom", "encrypted files", "readme.txt"),
         ("T1486", "Impact", 0.7)),
        (("beacon", "c2", "callback", "command and control"),
         ("T1071.001", "Command and Control", 0.6)),
        (("sql injection", "union select", "xp_cmdshell"),
         ("T1190", "Initial Access", 0.7)),
        (("phishing", "credential harvest", "fake login"),
         ("T1566.002", "Phishing", 0.6)),
        (("malware", "virus", "trojan"),
         ("T1204.002", "User Execution", 0.5)),
    ]
    for keywords, result in rules:
        if any(k in text for k in keywords):
            return result
    return ("T0000", "Unknown", 0.0)


def compute_verdict(
    classification: dict,
    threat_enrichment: dict,
    false_positive_matches: list,
    log_results: list,
    alert_description: str,
    confidence_threshold: float = 0.6,
) -> dict:
    """Fuse the investigation signals into one go/no-go decision.

    Decision rules (all deterministic, in priority order):
      1. Strong known-FP history (>=3 confirms) + LLM not very confident
         malicious -> FALSE_POSITIVE.
      2. Strong threat-intel score (>=75) + corroborating logs (>0)
         -> MALICIOUS escalate (even if the LLM was unsure; the intel and
         logs speak for themselves; escalation is the safe failure mode).
      3. LLM MALICIOUS with confidence >= threshold and logs present
         -> MALICIOUS.
      4. LLM FALSE_POSITIVE with confidence >= threshold -> FALSE_POSITIVE.
      5. Everything else -> NEEDS_REVIEW (human decides).

    The returned dict always has: decision, confidence (0..1), escalate
    (bool), why (list of human-readable reasons), attack_guess, and a
    signals breakdown. It never raises on odd input shapes.
    """
    reasons = []
    classification = classification or {}
    llm_verdict = str(classification.get("verdict", "NEEDS_REVIEW")).upper()
    try:
        llm_confidence = max(0.0, min(1.0, float(classification.get("confidence", 0.0))))
    except (TypeError, ValueError):
        llm_confidence = 0.0

    threat = _threat_score_of(threat_enrichment)
    fp_count = _fp_count_of(false_positive_matches)
    volume = _volume_score(log_results)
    tactic_id, tactic, tactic_conf = guess_attack_tactic(alert_description)

    if threat >= 0.75:
        reasons.append(f"AbuseIPDB score {int(threat*100)}/100 is highly malicious")
    elif threat >= 0.50:
        reasons.append(f"AbuseIPDB score {int(threat*100)}/100 is malicious")

    if fp_count >= HIGH_FP_COUNT:
        reasons.append(
            f"IP confirmed false-positive {fp_count} time(s) by analysts"
        )
    elif fp_count:
        reasons.append(f"IP has {fp_count} prior false-positive confirmation(s)")

    if volume >= 1.0:
        reasons.append(f"{len(log_results)} corroborating log events found")
    elif volume > 0:
        reasons.append(f"{len(log_results)} log event(s) corroborate the alert")

    if tactic_id != "T0000":
        reasons.append(f"Alert text suggests {tactic} ({tactic_id}) — guessed, not confirmed")

    # ---- decision -------------------------------------------------------
    decision = VERDICT_NEEDS_REVIEW
    escalate = False

    if fp_count >= HIGH_FP_COUNT and not (llm_verdict == VERDICT_MALICIOUS and llm_confidence >= 0.9):
        decision = VERDICT_FALSE_POSITIVE
        reasons.append("Known benign pattern — do not escalate")
    elif threat >= 0.75 and volume > 0:
        decision = VERDICT_MALICIOUS
        escalate = True
        reasons.append("Threat intel + corroborating logs — escalate regardless of LLM")
    elif llm_verdict == VERDICT_MALICIOUS and llm_confidence >= confidence_threshold and volume > 0:
        decision = VERDICT_MALICIOUS
        escalate = True
        reasons.append(f"LLM malicious at {llm_confidence:.2f} confidence with logs present")
    elif llm_verdict == VERDICT_FALSE_POSITIVE and llm_confidence >= confidence_threshold:
        decision = VERDICT_FALSE_POSITIVE
        reasons.append(f"LLM false-positive at {llm_confidence:.2f} confidence")
    else:
        reasons.append("No conclusive signal — human review required")

    # ---- overall confidence (how sure are we about this decision?) ------
    confidence = llm_confidence
    if decision == VERDICT_FALSE_POSITIVE and fp_count >= HIGH_FP_COUNT:
        confidence = max(confidence, 0.9)
    if decision == VERDICT_MALICIOUS and threat >= 0.75:
        confidence = max(confidence, 0.85)

    confidence = max(0.0, min(1.0, confidence))

    return {
        "decision": decision,
        "confidence": round(confidence, 2),
        "escalate": escalate,
        "why": reasons,
        "attack_guess": {
            "technique_id": tactic_id,
            "tactic": tactic,
            "confidence": tactic_conf,
        },
        "signals": {
            "llm_verdict": llm_verdict,
            "llm_confidence": round(llm_confidence, 2),
            "threat_score_0_1": round(threat, 2),
            "fp confirmations": fp_count,
            "log_events": len(log_results or []),
        },
    }
