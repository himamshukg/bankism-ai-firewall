import re
from typing import Optional, Tuple, List
from app.models import BankingIntent, ParsedBankingRequest, ThreatCategory
from app.rules import MAX_P2P_TRANSFER_LIMIT, MIN_P2P_TRANSFER_LIMIT


class BankingRequestParser:
    """Deterministic natural language parser and strict schema validator for banking intents."""

    # Patterns for intent classification
    BALANCE_PATTERNS = [
        re.compile(r"(?i)\b(what('s|\s+is)?|show|check|view|get|tell\s+me)\s+(my\s+)?(current\s+)?(checking\s+|savings\s+)?(account\s+)?balance\b"),
        re.compile(r"(?i)\bhow\s+much\s+(money|cash|funds)\s+(do\s+i\s+have|in\s+my\s+account)\b"),
        re.compile(r"(?i)\b(account|available)\s+balance\b"),
    ]

    TRANSFER_VERB_PATTERNS = [
        re.compile(r"(?i)\b(transfer|send|wire|pay|remit)\b"),
    ]

    HISTORY_PATTERNS = [
        re.compile(r"(?i)\b(transaction\s+history|recent\s+transactions|past\s+transfers|statement)\b"),
    ]

    ACCOUNT_INFO_PATTERNS = [
        re.compile(r"(?i)\b(account\s+numbers?|routing\s+number|account\s+details|my\s+accounts?)\b"),
    ]

    # Amount extraction regex
    # Matches: $45, $45.50, 45.50 dollars, -$50, $0, etc.
    AMOUNT_PATTERN = re.compile(r"(?<![A-Za-z0-9_])(-?\$?\s*([0-9]{1,3}(?:,[0-9]{3})*|\d+)(?:\.\d{1,4})?|\$0(?:\.00)?)\s*(?:usd|dollars|bucks)?(?![A-Za-z0-9_])", re.IGNORECASE)

    # Negative amount detection (ensure minus is not part of a hyphenated code like AUTH-EXEC-9942)
    NEGATIVE_AMOUNT_PATTERN = re.compile(r"(?i)((?<![A-Za-z0-9_])-\s*\$?\d+|\bnegative\s+\$?\d+)")

    # Ambiguous amount indicators
    AMBIGUOUS_AMOUNT_WORDS = [
        "some cash", "some money", "a bit of money", "a little cash", "few dollars",
        "everything", "all funds", "all my money", "all cash", "the rest"
    ]

    # Recipient extraction patterns
    # e.g. "to Alice", "to @alice", "to Bob Smith"
    RECIPIENT_PATTERNS = [
        re.compile(r"(?i)\bto\s+([@A-Za-z][A-Za-z0-9_.]*(?:\s+[A-Za-z][A-Za-z0-9_.]+)?)(?:\s+(?:for|with\s+memo|from|on|right\s+now|immediately|asap|tomorrow|\$?\d+)|[.,;:!?]|\s*$)"),
        re.compile(r"(?i)\bpay\s+([@A-Za-z][A-Za-z0-9_.]*(?:\s+[A-Za-z][A-Za-z0-9_.]+)?)\s+(\$?\d+)"),
    ]

    # Memo extraction
    MEMO_PATTERN = re.compile(r"(?i)\b(?:with\s+memo|memo)\s*:\s*(.+)$")
    FOR_MEMO_PATTERN = re.compile(r"(?i)\bfor\s+([A-Za-z0-9\s,.'\"_-]{2,60})(?:\s+(?:with\s+memo|memo|\.|$))")

    @classmethod
    def classify_intent(cls, text: str) -> BankingIntent:
        """Deterministically determine the core banking action requested."""
        for pattern in cls.BALANCE_PATTERNS:
            if pattern.search(text):
                return BankingIntent.BALANCE_INQUIRY

        for pattern in cls.HISTORY_PATTERNS:
            if pattern.search(text):
                return BankingIntent.TRANSACTION_HISTORY

        for pattern in cls.ACCOUNT_INFO_PATTERNS:
            if pattern.search(text):
                return BankingIntent.ACCOUNT_DETAILS

        for pattern in cls.TRANSFER_VERB_PATTERNS:
            if pattern.search(text):
                return BankingIntent.TRANSFER

        return BankingIntent.UNKNOWN

    @classmethod
    def extract_amount(cls, text: str) -> Tuple[Optional[float], Optional[str], List[str]]:
        """
        Extract numerical amount and validate bounds.
        Returns (amount_val, currency, errors_list).
        """
        errors = []

        # Check negative amount first
        if cls.NEGATIVE_AMOUNT_PATTERN.search(text):
            errors.append("Negative transaction amount detected.")
            return -1.0, "USD", errors

        # Check ambiguous amount words
        lower_text = text.lower()
        for phrase in cls.AMBIGUOUS_AMOUNT_WORDS:
            if phrase in lower_text:
                errors.append(f"Ambiguous or non-deterministic amount phrase detected: '{phrase}'.")
                return None, "USD", errors

        # Find numbers with currency
        matches = list(cls.AMOUNT_PATTERN.finditer(text))
        valid_candidates = []

        for m in matches:
            raw_val = m.group(0).replace("$", "").replace(",", "").strip()
            # Clean possible trailing 'dollars'/'usd'
            raw_val = re.sub(r"(?i)(usd|dollars|bucks)", "", raw_val).strip()
            try:
                val = float(raw_val)
                valid_candidates.append(val)
            except ValueError:
                continue

        if not valid_candidates:
            errors.append("Missing required transaction amount.")
            return None, "USD", errors

        # Take the most prominent amount (first valid transfer amount)
        amount = valid_candidates[0]

        # Boundary checks
        if amount <= 0:
            errors.append(f"Invalid non-positive transaction amount (${amount:.2f}). Must be greater than $0.00.")
        elif amount > MAX_P2P_TRANSFER_LIMIT:
            errors.append(f"Amount ${amount:,.2f} exceeds maximum retail P2P limit of ${MAX_P2P_TRANSFER_LIMIT:,.2f}.")

        return amount, "USD", errors

    @classmethod
    def extract_recipient(cls, text: str) -> Tuple[Optional[str], List[str]]:
        """Extract and sanitize transfer recipient."""
        errors = []
        cleaned_recipient = None

        for pattern in cls.RECIPIENT_PATTERNS:
            match = pattern.search(text)
            if match:
                raw_rec = match.group(1).strip()
                # Stop at common prepositions or noise
                raw_rec = re.split(r"(?i)\b(for|with|from|using|on)\b", raw_rec)[0].strip()
                raw_rec = raw_rec.rstrip(".,;:!?")
                if len(raw_rec) > 1:
                    cleaned_recipient = raw_rec
                    break

        if not cleaned_recipient:
            errors.append("Missing or unrecognized recipient for transfer.")
            return None, errors

        # Validate recipient string against suspicious control characters
        if re.search(r"[<>{};\'\"`=\\\[\]]", cleaned_recipient):
            errors.append(f"Recipient name contains invalid characters: '{cleaned_recipient}'.")
            return None, errors

        # Disallow recipient being a reserved keyword
        disallowed_recipients = {"myself", "attacker", "hacker", "system", "admin", "root", "nobody", "null", "undefined"}
        if cleaned_recipient.lower() in disallowed_recipients:
            errors.append(f"Recipient '{cleaned_recipient}' is a disallowed or high-risk target.")
            return None, errors

        return cleaned_recipient, errors

    @classmethod
    def extract_memo(cls, text: str) -> Optional[str]:
        """Extract payment memo or notes if present."""
        memo_match = cls.MEMO_PATTERN.search(text)
        if memo_match:
            return memo_match.group(1).strip()

        for_match = cls.FOR_MEMO_PATTERN.search(text)
        if for_match:
            candidate = for_match.group(1).strip()
            # Verify candidate doesn't conflict with transfer recipient or amount
            if not cls.AMOUNT_PATTERN.match(candidate):
                return candidate

        return None

    @classmethod
    def parse_and_validate(cls, text: str) -> Tuple[ParsedBankingRequest, List[str], List[str]]:
        """
        Fully parses natural language banking request and deterministically validates required fields.
        Returns: (parsed_request, missing_or_invalid_fields, validation_threats)
        """
        intent = cls.classify_intent(text)
        missing_fields: List[str] = []
        threats: List[str] = []

        if intent == BankingIntent.UNKNOWN:
            missing_fields.append("intent")
            threats.append(ThreatCategory.AMBIGUOUS_REQUEST.value)
            parsed = ParsedBankingRequest(
                intent=BankingIntent.UNKNOWN,
                confidence=0.0,
                missing_fields=missing_fields
            )
            return parsed, missing_fields, threats

        if intent in (BankingIntent.BALANCE_INQUIRY, BankingIntent.ACCOUNT_DETAILS, BankingIntent.TRANSACTION_HISTORY):
            # Read-only inquiries don't require amount or recipient
            parsed = ParsedBankingRequest(
                intent=intent,
                source_account="Checking (#4829)",
                confidence=0.98,
                missing_fields=[]
            )
            return parsed, missing_fields, threats

        if intent == BankingIntent.TRANSFER:
            amount, currency, amount_errors = cls.extract_amount(text)
            recipient, recipient_errors = cls.extract_recipient(text)
            memo = cls.extract_memo(text)

            if amount is None or amount <= 0 or amount > MAX_P2P_TRANSFER_LIMIT:
                missing_fields.append("amount")
                if amount is not None and (amount <= 0 or amount > MAX_P2P_TRANSFER_LIMIT):
                    threats.append(ThreatCategory.MALFORMED_AMOUNT.value)
                else:
                    threats.append(ThreatCategory.AMBIGUOUS_REQUEST.value)

            if recipient is None:
                missing_fields.append("recipient")
                if ThreatCategory.AMBIGUOUS_REQUEST.value not in threats:
                    threats.append(ThreatCategory.AMBIGUOUS_REQUEST.value)

            confidence = 0.95
            if missing_fields:
                confidence = max(0.20, 0.95 - (len(missing_fields) * 0.40))

            parsed = ParsedBankingRequest(
                intent=intent,
                amount=amount,
                currency=currency,
                recipient=recipient,
                source_account="Checking (#4829)",
                memo=memo,
                confidence=confidence,
                missing_fields=missing_fields
            )
            return parsed, missing_fields, threats

        # Fallback unknown
        missing_fields.append("intent")
        threats.append(ThreatCategory.AMBIGUOUS_REQUEST.value)
        return ParsedBankingRequest(intent=BankingIntent.UNKNOWN, confidence=0.1, missing_fields=missing_fields), missing_fields, threats
