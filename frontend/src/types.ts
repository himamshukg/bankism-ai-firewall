export type Decision = 'APPROVE' | 'BLOCK';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ParsedBankingRequest {
  intent: string;
  amount: number | null;
  currency: string;
  recipient: string | null;
  source_account: string | null;
  memo: string | null;
  confidence: number;
  missing_fields: string[];
}

export interface BankingActionReceipt {
  success: boolean;
  status: string;
  transaction_id: string | null;
  message: string;
  timestamp: string;
  details?: Record<string, any> | null;
}

export interface ScanResult {
  scan_id: string;
  timestamp: string;
  prompt: string;
  decision: Decision;
  risk_level: RiskLevel;
  risk_score: number;
  threat_categories: string[];
  rationale: string;
  parsed_request: ParsedBankingRequest | null;
  requires_human_review: boolean;
  execution_receipt: BankingActionReceipt | null;
}

export interface SampleRequest {
  id: string;
  category: string;
  title: string;
  prompt: string;
  expected_decision: Decision;
  description: string;
}

export interface AccountInfo {
  account_id: string;
  account_name: string;
  account_number: string;
  balance: number;
  currency: string;
}

export interface TransactionRecord {
  id: string;
  timestamp: string;
  type: string;
  amount: number;
  recipient: string | null;
  source_account: string;
  memo: string | null;
  status: string;
}

export interface SystemStats {
  total_scans: number;
  approved_count: number;
  blocked_count: number;
  human_review_count: number;
  average_risk_score: number;
  threat_distribution: Record<string, number>;
  mock_executions_total: number;
}
