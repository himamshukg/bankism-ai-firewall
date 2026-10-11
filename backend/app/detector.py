import base64
import re
import unicodedata
from typing import Dict, List, Tuple, Any

from app.rules import (
    PROMPT_INJECTION_PATTERNS,
    JAILBREAK_PATTERNS,
    SYSTEM_EXTRACTION_PATTERNS,
    AUTHORITY_SPOOFING_PATTERNS,
    MALICIOUS_PAYLOAD_PATTERNS,
    MEMO_INDIRECT_INJECTION_PATTERNS,
    DELIMITER_PATTERNS,
    BASE64_PATTERN,
    ZERO_WIDTH_CHARS,
)
from app.models import ThreatCategory


class ThreatDetector:
    """Multi-layer heuristic and signature analyzer for AI banking firewall."""

    @staticmethod
    def normalize_text(text: str) -> str:
        """Strip invisible characters, normalize unicode homoglyphs and NFKD representation."""
        # Check and strip zero width characters
        cleaned = "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARS)
        # Unicode normalization (e.g., fullwidth characters to standard ASCII)
        normalized = unicodedata.normalize("NFKD", cleaned)
        # Collapse multiple spaces
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized

    @classmethod
    def detect_obfuscation(cls, text: str) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Detect zero-width spaces, base64 payloads, leetspeak, or evasive delimiters."""
        threats: List[str] = []
        details: List[Dict[str, Any]] = []

        # 1. Zero-width character inspection
        hidden_chars_count = sum(1 for ch in text if ch in ZERO_WIDTH_CHARS)
        if hidden_chars_count > 0:
            threats.append(ThreatCategory.OBFUSCATION_EVASION.value)
            details.append({
                "type": "ZERO_WIDTH_CHARACTER_INJECTION",
                "count": hidden_chars_count,
                "description": f"Found {hidden_chars_count} hidden zero-width/unicode characters used for keyword evasion."
            })

        # 2. Base64 payload inspection
        for match in BASE64_PATTERN.finditer(text):
            candidate = match.group(0)
            if len(candidate) >= 16:  # Significant encoded length
                try:
                    decoded_bytes = base64.b64decode(candidate)
                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore").lower()
                    suspicious_keywords = ["transfer", "funds", "money", "ignore", "prompt", "system", "override", "root", "admin", "bypass", "rule", "exploit"]
                    found_kw = [kw for kw in suspicious_keywords if kw in decoded_str]
                    if found_kw or len(decoded_str) > 10:
                        threats.append(ThreatCategory.OBFUSCATION_EVASION.value)
                        details.append({
                            "type": "BASE64_ENCODED_PAYLOAD",
                            "encoded_sample": candidate[:30] + ("..." if len(candidate) > 30 else ""),
                            "decoded_sample": decoded_str[:60] + ("..." if len(decoded_str) > 60 else ""),
                            "trigger_keywords": found_kw,
                            "description": "Base64 encoded string detected concealing instructions or keywords."
                        })
                except Exception:
                    pass

        # 3. Delimiter Smashing / Structure Smuggling
        for pattern in DELIMITER_PATTERNS:
            if pattern.search(text):
                threats.append(ThreatCategory.PROMPT_INJECTION.value)
                details.append({
                    "type": "DELIMITER_SMASHING",
                    "description": "Detected system fence or delimiter injection (e.g., '--- END OF PROMPT ---' or '```system')."
                })
                break

        # 4. Spaced/Leetspeak words (e.g., "i g n o r e" or "1 g n 0 r 3")
        leetspeak_ignore = re.search(r"(?i)\b(i[\s._-]*g[\s._-]*n[\s._-]*o[\s._-]*r[\s._-]*e|1[\s._-]*g[\s._-]*n[\s._-]*0[\s._-]*r[\s._-]*3)\b", text)
        if leetspeak_ignore and "ignore" not in text.lower():
            threats.append(ThreatCategory.OBFUSCATION_EVASION.value)
            details.append({
                "type": "LEETSPEAK_KEYWORD_EVASION",
                "sample": leetspeak_ignore.group(0),
                "description": "Detected obfuscated keyword variation intended to bypass simple string matchers."
            })

        return threats, details

    @classmethod
    def detect_prompt_injection(cls, normalized_text: str) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Identify direct prompt injection & policy override vectors."""
        threats: List[str] = []
        details: List[Dict[str, Any]] = []

        for pattern in PROMPT_INJECTION_PATTERNS:
            match = pattern.search(normalized_text)
            if match:
                threats.append(ThreatCategory.PROMPT_INJECTION.value)
                details.append({
                    "type": "PROMPT_INJECTION_INSTRUCTION",
                    "snippet": match.group(0),
                    "description": "Detected instruction override attempting to disrupt core system guidance or safety constraints."
                })
                break

        return threats, details

    @classmethod
    def detect_jailbreak(cls, normalized_text: str) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Identify DAN, roleplay jailbreaks, developer mode, and root escalations."""
        threats: List[str] = []
        details: List[Dict[str, Any]] = []

        for pattern in JAILBREAK_PATTERNS:
            match = pattern.search(normalized_text)
            if match:
                threats.append(ThreatCategory.JAILBREAK_ATTEMPT.value)
                details.append({
                    "type": "JAILBREAK_SIGNATURE",
                    "snippet": match.group(0),
                    "description": "Detected jailbreak persona adoption or developer mode bypass request."
                })
                break

        return threats, details

    @classmethod
    def detect_system_extraction(cls, normalized_text: str) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Detect attempts to dump system prompt or internal rules."""
        threats: List[str] = []
        details: List[Dict[str, Any]] = []

        for pattern in SYSTEM_EXTRACTION_PATTERNS:
            match = pattern.search(normalized_text)
            if match:
                threats.append(ThreatCategory.SYSTEM_EXTRACTION.value)
                details.append({
                    "type": "SYSTEM_PROMPT_EXTRACTION",
                    "snippet": match.group(0),
                    "description": "Detected probing pattern attempting to exfiltrate system prompt or hidden security directives."
                })
                break

        return threats, details

    @classmethod
    def detect_authority_spoofing(cls, normalized_text: str) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Identify social engineering claims of executive/auditor override."""
        threats: List[str] = []
        details: List[Dict[str, Any]] = []

        for pattern in AUTHORITY_SPOOFING_PATTERNS:
            match = pattern.search(normalized_text)
            if match:
                threats.append(ThreatCategory.POLICY_OVERRIDE.value)
                details.append({
                    "type": "AUTHORITY_SPOOFING",
                    "snippet": match.group(0),
                    "description": "Detected fraudulent authority claim or emergency bypass token."
                })
                break

        return threats, details

    @classmethod
    def inspect_memo(cls, memo: str) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Strict untrusted memo inspector: check for SQLi, XSS, shellcode, and indirect injection."""
        threats: List[str] = []
        details: List[Dict[str, Any]] = []

        if not memo or not memo.strip():
            return threats, details

        # Check code / malicious payloads
        for pattern in MALICIOUS_PAYLOAD_PATTERNS:
            match = pattern.search(memo)
            if match:
                threats.append(ThreatCategory.MALICIOUS_MEMO.value)
                details.append({
                    "type": "CODE_OR_DATA_INJECTION_IN_MEMO",
                    "snippet": match.group(0),
                    "description": f"Untrusted payment memo contains dangerous payload pattern ({match.group(0)})."
                })
                break

        # Check secondary / indirect prompt injection inside memo
        for pattern in MEMO_INDIRECT_INJECTION_PATTERNS:
            match = pattern.search(memo)
            if match:
                if ThreatCategory.MALICIOUS_MEMO.value not in threats:
                    threats.append(ThreatCategory.MALICIOUS_MEMO.value)
                details.append({
                    "type": "INDIRECT_PROMPT_INJECTION_IN_MEMO",
                    "snippet": match.group(0),
                    "description": "Untrusted memo contains secondary command directed at human reviewer or downstream banking agent."
                })
                break

        return threats, details

    @classmethod
    def scan_all(cls, raw_text: str, extracted_memo: str = "") -> Tuple[List[str], List[Dict[str, Any]], str]:
        """Run full threat detection suite across raw and normalized text."""
        all_threats: List[str] = []
        all_details: List[Dict[str, Any]] = []

        # 1. Raw obfuscation check
        obf_threats, obf_details = cls.detect_obfuscation(raw_text)
        all_threats.extend(obf_threats)
        all_details.extend(obf_details)

        # 2. Text normalization
        normalized = cls.normalize_text(raw_text)

        # 3. Direct Prompt Injection
        pi_threats, pi_details = cls.detect_prompt_injection(normalized)
        all_threats.extend(pi_threats)
        all_details.extend(pi_details)

        # 4. Jailbreak
        jb_threats, jb_details = cls.detect_jailbreak(normalized)
        all_threats.extend(jb_threats)
        all_details.extend(jb_details)

        # 5. System Extraction
        se_threats, se_details = cls.detect_system_extraction(normalized)
        all_threats.extend(se_threats)
        all_details.extend(se_details)

        # 6. Authority Spoofing
        as_threats, as_details = cls.detect_authority_spoofing(normalized)
        all_threats.extend(as_threats)
        all_details.extend(as_details)

        # 7. Memo Inspection (both explicitly extracted memo and any "memo:" section found in text)
        memo_candidates = [extracted_memo] if extracted_memo else []
        memo_inline_match = re.search(r"(?i)\bmemo\s*:\s*(.+)$", normalized)
        if memo_inline_match:
            memo_candidates.append(memo_inline_match.group(1).strip())

        for memo_text in memo_candidates:
            if memo_text:
                m_threats, m_details = cls.inspect_memo(memo_text)
                all_threats.extend(m_threats)
                all_details.extend(m_details)

        # Deduplicate threat categories while preserving order
        unique_threats = list(dict.fromkeys(all_threats))
        return unique_threats, all_details, normalized
