import type {
  ScanResult,
  SampleRequest,
  SystemStats,
  AccountInfo,
  TransactionRecord,
} from './types';

const API_BASE = '/api';

export async function scanRequest(prompt: string, executeAction: boolean = false): Promise<ScanResult> {
  const endpoint = executeAction ? `${API_BASE}/scan-and-execute` : `${API_BASE}/scan`;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt, execute_action: executeAction }),
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Firewall scan request failed: ${res.status} ${errorText}`);
  }

  return res.json();
}

export async function fetchSamples(): Promise<SampleRequest[]> {
  const res = await fetch(`${API_BASE}/samples`);
  if (!res.ok) throw new Error('Failed to fetch samples');
  return res.json();
}

export async function fetchStats(): Promise<SystemStats> {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) throw new Error('Failed to fetch system stats');
  return res.json();
}

export async function fetchAccounts(): Promise<AccountInfo[]> {
  const res = await fetch(`${API_BASE}/accounts`);
  if (!res.ok) throw new Error('Failed to fetch mock accounts');
  return res.json();
}

export async function fetchTransactions(): Promise<TransactionRecord[]> {
  const res = await fetch(`${API_BASE}/transactions`);
  if (!res.ok) throw new Error('Failed to fetch transaction records');
  return res.json();
}

export async function fetchHistory(): Promise<ScanResult[]> {
  const res = await fetch(`${API_BASE}/history`);
  if (!res.ok) throw new Error('Failed to fetch scan history');
  return res.json();
}

export async function resetSystem(): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE}/reset`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to reset system state');
  return res.json();
}
