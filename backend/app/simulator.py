import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from app.models import (
    Decision,
    ScanResult,
    BankingIntent,
    BankingActionReceipt,
    AccountInfo,
    TransactionRecord,
)


class MockBankingSimulator:
    """
    Mock Banking Execution Core.
    CRITICAL SECURITY INVARIANT:
    Must NEVER connect to a real bank, and MUST NEVER execute any action for blocked or unapproved requests.
    """

    INITIAL_ACCOUNTS = {
        "acc-1": {
            "account_id": "acc-1",
            "account_name": "Premier Checking",
            "account_number": "Checking (#4829)",
            "balance": 4250.00,
            "currency": "USD",
        },
        "acc-2": {
            "account_id": "acc-2",
            "account_name": "High-Yield Savings",
            "account_number": "Savings (#9102)",
            "balance": 12800.00,
            "currency": "USD",
        },
    }

    def __init__(self):
        self.accounts: Dict[str, Dict] = {}
        self.transactions: List[TransactionRecord] = []
        self.reset()

    def reset(self):
        """Reset mock ledger to initial baseline."""
        self.accounts = {
            k: dict(v) for k, v in self.INITIAL_ACCOUNTS.items()
        }
        self.transactions = [
            TransactionRecord(
                id="TX-INIT-001",
                timestamp="2026-10-10T14:30:00Z",
                type="DEPOSIT",
                amount=2500.00,
                recipient=None,
                source_account="Checking (#4829)",
                memo="Payroll Direct Deposit",
                status="SETTLED"
            ),
            TransactionRecord(
                id="TX-INIT-002",
                timestamp="2026-10-10T19:15:00Z",
                type="TRANSFER",
                amount=65.00,
                recipient="Trader Joe's",
                source_account="Checking (#4829)",
                memo="Weekly groceries",
                status="SETTLED"
            )
        ]

    def get_accounts(self) -> List[AccountInfo]:
        return [AccountInfo(**acc) for acc in self.accounts.values()]

    def get_transactions(self) -> List[TransactionRecord]:
        return list(reversed(self.transactions))

    def execute_action(self, scan_result: ScanResult) -> BankingActionReceipt:
        """
        Execute mock banking action.
        FAIL-CLOSED ASSERTION: Strictly rejects execution if firewall decision is not APPROVE.
        """
        now_str = datetime.now(timezone.utc).isoformat()

        # 1. HARD SECURITY GATE: Never execute if blocked
        if scan_result.decision != Decision.APPROVE:
            return BankingActionReceipt(
                success=False,
                status="PREVENTED_BY_FIREWALL",
                transaction_id=None,
                message=f"SIMULATOR REFUSAL: Execution denied. Request was blocked by Bankism AI Firewall. Risk Score: {scan_result.risk_score}/100.",
                timestamp=now_str,
                details={
                    "threat_categories": scan_result.threat_categories,
                    "rationale": scan_result.rationale
                }
            )

        # 2. Verify parsed request exists
        parsed = scan_result.parsed_request
        if not parsed:
            return BankingActionReceipt(
                success=False,
                status="VALIDATION_ERROR",
                transaction_id=None,
                message="SIMULATOR REFUSAL: Missing parsed request details.",
                timestamp=now_str
            )

        # 3. Handle Balance Inquiry
        if parsed.intent == BankingIntent.BALANCE_INQUIRY:
            acc = self.accounts["acc-1"]
            return BankingActionReceipt(
                success=True,
                status="COMPLETED",
                transaction_id=f"INQ-{uuid.uuid4().hex[:8].upper()}",
                message=f"Mock Balance Inquiry: {acc['account_name']} ({acc['account_number']}) current balance is ${acc['balance']:,.2f} {acc['currency']}.",
                timestamp=now_str,
                details={
                    "account_name": acc["account_name"],
                    "account_number": acc["account_number"],
                    "balance": acc["balance"],
                    "currency": acc["currency"]
                }
            )

        # 4. Handle Account Details
        if parsed.intent == BankingIntent.ACCOUNT_DETAILS:
            return BankingActionReceipt(
                success=True,
                status="COMPLETED",
                transaction_id=f"INFO-{uuid.uuid4().hex[:8].upper()}",
                message="Mock Account Details retrieved successfully.",
                timestamp=now_str,
                details={
                    "accounts": list(self.accounts.values())
                }
            )

        # 5. Handle Transaction History
        if parsed.intent == BankingIntent.TRANSACTION_HISTORY:
            return BankingActionReceipt(
                success=True,
                status="COMPLETED",
                transaction_id=f"HIST-{uuid.uuid4().hex[:8].upper()}",
                message=f"Mock Transaction History: {len(self.transactions)} recent records found.",
                timestamp=now_str,
                details={
                    "recent_count": len(self.transactions)
                }
            )

        # 6. Handle Transfer
        if parsed.intent == BankingIntent.TRANSFER:
            if not parsed.amount or parsed.amount <= 0:
                return BankingActionReceipt(
                    success=False,
                    status="FAILED_VALIDATION",
                    transaction_id=None,
                    message="SIMULATOR REFUSAL: Invalid transfer amount.",
                    timestamp=now_str
                )

            if not parsed.recipient:
                return BankingActionReceipt(
                    success=False,
                    status="FAILED_VALIDATION",
                    transaction_id=None,
                    message="SIMULATOR REFUSAL: Invalid or missing recipient.",
                    timestamp=now_str
                )

            # Check sufficient funds in mock checking account
            checking_acc = self.accounts["acc-1"]
            if checking_acc["balance"] < parsed.amount:
                return BankingActionReceipt(
                    success=False,
                    status="INSUFFICIENT_FUNDS",
                    transaction_id=None,
                    message=f"Mock Transaction Failed: Insufficient funds. Available: ${checking_acc['balance']:,.2f}, Requested: ${parsed.amount:,.2f}.",
                    timestamp=now_str
                )

            # Deduct balance
            checking_acc["balance"] = round(checking_acc["balance"] - parsed.amount, 2)
            tx_id = f"TX-MOCK-{uuid.uuid4().hex[:8].upper()}"

            record = TransactionRecord(
                id=tx_id,
                timestamp=now_str,
                type="TRANSFER",
                amount=parsed.amount,
                recipient=parsed.recipient,
                source_account=checking_acc["account_number"],
                memo=parsed.memo,
                status="COMPLETED"
            )
            self.transactions.append(record)

            return BankingActionReceipt(
                success=True,
                status="COMPLETED",
                transaction_id=tx_id,
                message=f"Mock P2P Transfer of ${parsed.amount:,.2f} to {parsed.recipient} executed successfully.",
                timestamp=now_str,
                details={
                    "recipient": parsed.recipient,
                    "amount": parsed.amount,
                    "new_balance": checking_acc["balance"],
                    "source_account": checking_acc["account_number"],
                    "memo": parsed.memo,
                }
            )

        # Unsupported or unknown intent
        return BankingActionReceipt(
            success=False,
            status="UNSUPPORTED_INTENT",
            transaction_id=None,
            message=f"SIMULATOR REFUSAL: Unsupported intent '{parsed.intent}'.",
            timestamp=now_str
        )
