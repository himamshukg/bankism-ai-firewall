from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class Decision(str, Enum):
    APPROVE = "APPROVE"
    BLOCK = "BLOCK"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK_ATTEMPT = "JAILBREAK_ATTEMPT"
    POLICY_OVERRIDE = "POLICY_OVERRIDE"
    MALICIOUS_MEMO = "MALICIOUS_MEMO"
    OBFUSCATION_EVASION = "OBFUSCATION_EVASION"
    AMBIGUOUS_REQUEST = "AMBIGUOUS_REQUEST"
    MALFORMED_AMOUNT = "MALFORMED_AMOUNT"
    UNAUTHORIZED_ACTION = "UNAUTHORIZED_ACTION"
    SYSTEM_EXTRACTION = "SYSTEM_EXTRACTION"
    CODE_INJECTION = "CODE_INJECTION"


class BankingIntent(str, Enum):
    TRANSFER = "TRANSFER"
    BALANCE_INQUIRY = "BALANCE_INQUIRY"
    ACCOUNT_DETAILS = "ACCOUNT_DETAILS"
    TRANSACTION_HISTORY = "TRANSACTION_HISTORY"
    UNKNOWN = "UNKNOWN"


class ParsedBankingRequest(BaseModel):
    intent: BankingIntent = BankingIntent.UNKNOWN
    amount: Optional[float] = None
    currency: str = "USD"
    recipient: Optional[str] = None
    source_account: Optional[str] = None
    memo: Optional[str] = None
    confidence: float = 0.0
    missing_fields: List[str] = Field(default_factory=list)


class BankingActionReceipt(BaseModel):
    success: bool
    status: str
    transaction_id: Optional[str] = None
    message: str
    timestamp: str
    details: Optional[Dict[str, Any]] = None


class ScanResult(BaseModel):
    scan_id: str
    timestamp: str
    prompt: str
    decision: Decision
    risk_level: RiskLevel
    risk_score: int = Field(ge=0, le=100)
    threat_categories: List[str] = Field(default_factory=list)
    rationale: str
    parsed_request: Optional[ParsedBankingRequest] = None
    requires_human_review: bool = False
    execution_receipt: Optional[BankingActionReceipt] = None


class ScanRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=2000, description="Natural language banking request")
    execute_action: bool = Field(default=False, description="Whether to execute mock banking action if approved")


class SampleRequest(BaseModel):
    id: str
    category: str
    title: str
    prompt: str
    expected_decision: Decision
    description: str


class AccountInfo(BaseModel):
    account_id: str
    account_name: str
    account_number: str
    balance: float
    currency: str = "USD"


class TransactionRecord(BaseModel):
    id: str
    timestamp: str
    type: str
    amount: float
    recipient: Optional[str] = None
    source_account: str
    memo: Optional[str] = None
    status: str


class SystemStats(BaseModel):
    total_scans: int
    approved_count: int
    blocked_count: int
    human_review_count: int
    average_risk_score: float
    threat_distribution: Dict[str, int]
    mock_executions_total: int
