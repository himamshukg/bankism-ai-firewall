from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.models import (
    ScanRequest,
    ScanResult,
    Decision,
    SystemStats,
    AccountInfo,
    TransactionRecord,
    SampleRequest,
)
from app.engine import FirewallEngine
from app.simulator import MockBankingSimulator
from app.rules import SAMPLE_REQUESTS

app = FastAPI(
    title="Bankism AI Firewall API",
    description="Blue-Team AI Firewall for Financial Natural-Language Agents and Copilots.",
    version="1.0.0"
)

# Enable CORS for local Vite frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory state
simulator = MockBankingSimulator()
scan_history: List[ScanResult] = []

stats_state = {
    "total_scans": 0,
    "approved_count": 0,
    "blocked_count": 0,
    "human_review_count": 0,
    "total_risk_score": 0,
    "threat_distribution": {},
    "mock_executions_total": 0,
}


def record_scan_metrics(scan: ScanResult):
    stats_state["total_scans"] += 1
    stats_state["total_risk_score"] += scan.risk_score

    if scan.decision == Decision.APPROVE:
        stats_state["approved_count"] += 1
    else:
        stats_state["blocked_count"] += 1

    if scan.requires_human_review:
        stats_state["human_review_count"] += 1

    for threat in scan.threat_categories:
        stats_state["threat_distribution"][threat] = stats_state["threat_distribution"].get(threat, 0) + 1

    if scan.execution_receipt and scan.execution_receipt.success:
        stats_state["mock_executions_total"] += 1

    # Keep latest 100 scans in history
    scan_history.insert(0, scan)
    if len(scan_history) > 100:
        scan_history.pop()


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Bankism AI Firewall",
        "version": "1.0.0",
        "mode": "FAIL_CLOSED"
    }


@app.post("/api/scan", response_model=ScanResult)
def scan_request(req: ScanRequest):
    """
    Scan natural-language banking request through the Bankism firewall.
    Optionally executes mock banking action if execute_action=True AND decision=APPROVE.
    """
    result = FirewallEngine.evaluate(req.prompt)

    # If execution requested, simulator strictly enforces decision == APPROVE
    if req.execute_action:
        receipt = simulator.execute_action(result)
        result.execution_receipt = receipt

    record_scan_metrics(result)
    return result


@app.post("/api/scan-and-execute", response_model=ScanResult)
def scan_and_execute(req: ScanRequest):
    """Convenience endpoint to scan and immediately simulate approved actions."""
    req.execute_action = True
    return scan_request(req)


@app.get("/api/history", response_model=List[ScanResult])
def get_scan_history():
    """Retrieve recent scan audit logs."""
    return scan_history


@app.get("/api/samples", response_model=List[SampleRequest])
def get_sample_requests():
    """Retrieve pre-configured benign and attack test vectors."""
    return [SampleRequest(**sample) for sample in SAMPLE_REQUESTS]


@app.get("/api/stats", response_model=SystemStats)
def get_statistics():
    """Retrieve aggregated firewall security metrics."""
    total = stats_state["total_scans"]
    avg_score = round(stats_state["total_risk_score"] / total, 1) if total > 0 else 0.0

    return SystemStats(
        total_scans=total,
        approved_count=stats_state["approved_count"],
        blocked_count=stats_state["blocked_count"],
        human_review_count=stats_state["human_review_count"],
        average_risk_score=avg_score,
        threat_distribution=stats_state["threat_distribution"],
        mock_executions_total=stats_state["mock_executions_total"],
    )


@app.get("/api/accounts", response_model=List[AccountInfo])
def get_accounts():
    """Retrieve current mock account balances."""
    return simulator.get_accounts()


@app.get("/api/transactions", response_model=List[TransactionRecord])
def get_transactions():
    """Retrieve mock banking transaction ledger."""
    return simulator.get_transactions()


@app.post("/api/reset")
def reset_system():
    """Reset simulator ledger and scan history to baseline."""
    simulator.reset()
    scan_history.clear()
    stats_state["total_scans"] = 0
    stats_state["approved_count"] = 0
    stats_state["blocked_count"] = 0
    stats_state["human_review_count"] = 0
    stats_state["total_risk_score"] = 0
    stats_state["threat_distribution"].clear()
    stats_state["mock_executions_total"] = 0
    return {"status": "success", "message": "Bankism mock simulator and metrics reset successfully."}
