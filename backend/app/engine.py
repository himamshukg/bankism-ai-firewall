import uuid
from datetime import datetime, timezone
from typing import List, Tuple

from app.models import (
    Decision,
    RiskLevel,
    ThreatCategory,
    ScanResult,
    ParsedBankingRequest,
    BankingIntent,
)
from app.detector import ThreatDetector
from app.parser import BankingRequestParser


class FirewallEngine:
    """
    Bankism AI Firewall Engine.
    Coordinates threat detection, deterministic intent parsing, risk calculation,
    and fail-closed decision enforcement.
    """

    @classmethod
    def evaluate(cls, raw_prompt: str) -> ScanResult:
        scan_id = f"SCAN-{uuid.uuid4().hex[:10].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # Step 1: Deterministic natural language banking parsing
        parsed, missing_fields, parse_threats = BankingRequestParser.parse_and_validate(raw_prompt)

        # Step 2: Multi-layer threat detection (including raw obfuscation, normalized text, and memo)
        extracted_memo = parsed.memo or ""
        detected_threats, threat_details, normalized_text = ThreatDetector.scan_all(
            raw_prompt, extracted_memo=extracted_memo
        )

        # Merge parsing threats (e.g., AMBIGUOUS_REQUEST, MALFORMED_AMOUNT) with detection threats
        combined_threats = list(dict.fromkeys(detected_threats + parse_threats))

        # Step 3: Risk score calculation (0 - 100)
        risk_score, rationale_reasons = cls._calculate_risk_and_rationale(
            combined_threats, parsed, missing_fields, threat_details
        )

        # Step 4: Determine Risk Level
        if risk_score >= 85:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 60:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 30:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        # Step 5: Fail-Closed Decision Enforcement
        # INVARIANT: Must NEVER approve if risk_score >= 30, or if any threats exist,
        # or if transfer is missing required fields, or if intent is unknown.
        is_blocked = False

        if risk_score >= 30:
            is_blocked = True
        if len(combined_threats) > 0:
            is_blocked = True
        if parsed.intent == BankingIntent.UNKNOWN:
            is_blocked = True
        if parsed.intent == BankingIntent.TRANSFER and (parsed.amount is None or parsed.recipient is None):
            is_blocked = True

        decision = Decision.BLOCK if is_blocked else Decision.APPROVE

        # Human review determination
        requires_human_review = (
            decision == Decision.BLOCK
            or (parsed.intent == BankingIntent.TRANSFER and parsed.amount is not None and parsed.amount >= 5000.0)
            or (30 <= risk_score <= 75)
        )

        # Synthesize clear rationale string
        if decision == Decision.APPROVE:
            rationale = (
                f"REQUEST APPROVED: Verified safe {parsed.intent.value} intent with valid schema parameters. "
                f"No injection vectors, jailbreak signatures, or suspicious memo payloads detected. "
                f"Risk assessment: {risk_score}/100 (LOW)."
            )
        else:
            reasons_joined = " | ".join(rationale_reasons) if rationale_reasons else "Failed deterministic validation policy."
            rationale = (
                f"REQUEST BLOCKED [Fail-Closed]: {reasons_joined} "
                f"Assigned Risk Score: {risk_score}/100 ({risk_level.value})."
            )

        return ScanResult(
            scan_id=scan_id,
            timestamp=timestamp,
            prompt=raw_prompt,
            decision=decision,
            risk_level=risk_level,
            risk_score=risk_score,
            threat_categories=combined_threats,
            rationale=rationale,
            parsed_request=parsed,
            requires_human_review=requires_human_review,
            execution_receipt=None
        )

    @staticmethod
    def _calculate_risk_and_rationale(
        threats: List[str],
        parsed: ParsedBankingRequest,
        missing_fields: List[str],
        threat_details: List[dict]
    ) -> Tuple[int, List[str]]:
        """Calculate numerical risk score (0-100) and assemble forensic rationale points."""
        score = 0
        reasons: List[str] = []

        # Severity weights per threat category
        weights = {
            ThreatCategory.PROMPT_INJECTION.value: 95,
            ThreatCategory.JAILBREAK_ATTEMPT.value: 95,
            ThreatCategory.SYSTEM_EXTRACTION.value: 90,
            ThreatCategory.POLICY_OVERRIDE.value: 90,
            ThreatCategory.MALICIOUS_MEMO.value: 88,
            ThreatCategory.CODE_INJECTION.value: 88,
            ThreatCategory.OBFUSCATION_EVASION.value: 85,
            ThreatCategory.MALFORMED_AMOUNT.value: 75,
            ThreatCategory.AMBIGUOUS_REQUEST.value: 65,
            ThreatCategory.UNAUTHORIZED_ACTION.value: 80,
        }

        # Apply threat weights
        for threat in threats:
            threat_weight = weights.get(threat, 60)
            score = max(score, threat_weight)

        # Collect specific explanations
        for detail in threat_details:
            reasons.append(detail.get("description", detail.get("type", "Security anomaly detected.")))

        # Handle Intent & Parameter Failures
        if parsed.intent == BankingIntent.UNKNOWN:
            score = max(score, 65)
            reasons.append("Unrecognized or non-banking intent. AI Firewall enforces fail-closed policy on ambiguous input.")

        if missing_fields:
            score = max(score, 65)
            reasons.append(f"Missing required parameters for banking action: {', '.join(missing_fields)}.")

        if ThreatCategory.MALFORMED_AMOUNT.value in threats and parsed.amount is not None:
            if parsed.amount <= 0:
                reasons.append(f"Invalid transaction amount: ${parsed.amount:.2f}. Amounts must be positive.")
            else:
                reasons.append(f"Transaction amount ${parsed.amount:,.2f} exceeds strict retail limit ($10,000.00).")

        # Baseline clean score
        if score == 0:
            # Benign baseline: low baseline score reflecting clean inspection
            if parsed.intent == BankingIntent.BALANCE_INQUIRY:
                score = 5
            elif parsed.intent == BankingIntent.TRANSFER:
                # Moderate scale for high amounts
                if parsed.amount and parsed.amount > 2000.0:
                    score = 15
                else:
                    score = 8
            else:
                score = 10

        # Cap score between 0 and 100
        score = min(100, max(0, score))
        return score, reasons
