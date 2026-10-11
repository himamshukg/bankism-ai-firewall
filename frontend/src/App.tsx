import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { StatsRibbon } from './components/StatsRibbon';
import { Scanner } from './components/Scanner';
import { VerdictCard } from './components/VerdictCard';
import { AuditLog } from './components/AuditLog';
import { ThreatStats } from './components/ThreatStats';
import { MockBankLedger } from './components/MockBankLedger';
import { JsonViewer } from './components/JsonViewer';

import type {
  ScanResult,
  SampleRequest,
  SystemStats,
  AccountInfo,
  TransactionRecord,
} from './types';
import * as api from './api';

export const App: React.FC = () => {
  const [prompt, setPrompt] = useState<string>('Please transfer $45.50 to Alice for dinner last night with memo: Pizza and drinks');
  const [executeAction, setExecuteAction] = useState<boolean>(true);
  const [samples, setSamples] = useState<SampleRequest[]>([]);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [accounts, setAccounts] = useState<AccountInfo[]>([]);
  const [transactions, setTransactions] = useState<TransactionRecord[]>([]);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [resetting, setResetting] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'audit' | 'threats' | 'ledger' | 'json'>('audit');

  // Load baseline system state on mount
  useEffect(() => {
    loadAllData();
  }, []);

  const loadAllData = async () => {
    try {
      const [fetchedSamples, fetchedStats, fetchedAccounts, fetchedTransactions, fetchedHistory] =
        await Promise.all([
          api.fetchSamples(),
          api.fetchStats(),
          api.fetchAccounts(),
          api.fetchTransactions(),
          api.fetchHistory(),
        ]);

      setSamples(fetchedSamples);
      setStats(fetchedStats);
      setAccounts(fetchedAccounts);
      setTransactions(fetchedTransactions);
      setHistory(fetchedHistory);
    } catch (err) {
      console.error('Failed to load initial Bankism firewall data:', err);
    }
  };

  const handleScan = async () => {
    if (!prompt.trim() || loading) return;

    setLoading(true);
    try {
      const result = await api.scanRequest(prompt, executeAction);
      setCurrentResult(result);

      // Refresh system state
      const [updatedStats, updatedAccounts, updatedTransactions, updatedHistory] =
        await Promise.all([
          api.fetchStats(),
          api.fetchAccounts(),
          api.fetchTransactions(),
          api.fetchHistory(),
        ]);

      setStats(updatedStats);
      setAccounts(updatedAccounts);
      setTransactions(updatedTransactions);
      setHistory(updatedHistory);
    } catch (err: any) {
      alert(`Firewall evaluation failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async () => {
    if (resetting) return;
    setResetting(true);
    try {
      await api.resetSystem();
      setCurrentResult(null);
      await loadAllData();
    } catch (err: any) {
      alert(`Reset failed: ${err.message}`);
    } finally {
      setResetting(false);
    }
  };

  const handleSelectFromHistory = (scan: ScanResult) => {
    setCurrentResult(scan);
    setPrompt(scan.prompt);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div>
      <Header onReset={handleReset} resetting={resetting} />

      <main className="app-container">
        {/* Metric Ribbon */}
        <StatsRibbon stats={stats} accounts={accounts} />

        {/* Primary Interactive Split View */}
        <div className="main-grid">
          <Scanner
            prompt={prompt}
            setPrompt={setPrompt}
            samples={samples}
            onScan={handleScan}
            loading={loading}
            executeAction={executeAction}
            setExecuteAction={setExecuteAction}
          />

          <VerdictCard result={currentResult} />
        </div>

        {/* Bottom Multi-Tab Analytics Section */}
        <div className="glass-panel tabs-section">
          <div className="tabs-nav">
            <button
              className={`tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
              onClick={() => setActiveTab('audit')}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="8" y1="6" x2="21" y2="6"></line>
                <line x1="8" y1="12" x2="21" y2="12"></line>
                <line x1="8" y1="18" x2="21" y2="18"></line>
                <line x1="3" y1="6" x2="3.01" y2="6"></line>
                <line x1="3" y1="12" x2="3.01" y2="12"></line>
                <line x1="3" y1="18" x2="3.01" y2="18"></line>
              </svg>
              Live Scan Audit Log
              <span className="tab-count">{history.length}</span>
            </button>

            <button
              className={`tab-btn ${activeTab === 'threats' ? 'active' : ''}`}
              onClick={() => setActiveTab('threats')}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path>
              </svg>
              Threat Radar & Categories
            </button>

            <button
              className={`tab-btn ${activeTab === 'ledger' ? 'active' : ''}`}
              onClick={() => setActiveTab('ledger')}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="2" y="4" width="20" height="16" rx="2"></rect>
                <line x1="2" y1="10" x2="22" y2="10"></line>
              </svg>
              Mock Banking Ledger
              <span className="tab-count">{transactions.length}</span>
            </button>

            <button
              className={`tab-btn ${activeTab === 'json' ? 'active' : ''}`}
              onClick={() => setActiveTab('json')}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="16 18 22 12 16 6"></polyline>
                <polyline points="8 6 2 12 8 18"></polyline>
              </svg>
              Raw Telemetry JSON
            </button>
          </div>

          <div className="tab-content">
            {activeTab === 'audit' && (
              <AuditLog history={history} onSelectScan={handleSelectFromHistory} />
            )}

            {activeTab === 'threats' && (
              <ThreatStats stats={stats} />
            )}

            {activeTab === 'ledger' && (
              <MockBankLedger accounts={accounts} transactions={transactions} />
            )}

            {activeTab === 'json' && (
              <JsonViewer data={currentResult} />
            )}
          </div>
        </div>

        {/* Footer */}
        <footer className="footer-container">
          <div>
            BANKISM AI FIREWALL // BLUE-TEAM FINANCIAL AGENT DEFENSE // BUILT FOR PROMPTWARS
          </div>
          <div style={{ marginTop: '0.25rem', color: 'var(--text-faint)' }}>
            Deterministic Fail-Closed Policy Enforcement • Zero Real Banking Connections • Zero Paid API Dependencies
          </div>
        </footer>
      </main>
    </div>
  );
};

export default App;
