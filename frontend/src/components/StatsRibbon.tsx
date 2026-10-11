import React from 'react';
import type { SystemStats, AccountInfo } from '../types';

interface StatsRibbonProps {
  stats: SystemStats | null;
  accounts: AccountInfo[];
}

export const StatsRibbon: React.FC<StatsRibbonProps> = ({ stats, accounts }) => {
  const total = stats?.total_scans ?? 0;
  const blocked = stats?.blocked_count ?? 0;
  const approved = stats?.approved_count ?? 0;
  const blockRate = total > 0 ? Math.round((blocked / total) * 100) : 0;
  const avgScore = stats?.average_risk_score ?? 0;

  const checkingAcc = accounts.find((a) => a.account_id === 'acc-1');

  return (
    <div className="stats-ribbon">
      <div className="stat-card">
        <div className="stat-label">Total Requests Scanned</div>
        <div className="stat-value">{total}</div>
        <div className="stat-meta">Inbound agent prompts</div>
      </div>

      <div className="stat-card stat-blocked">
        <div className="stat-label">Threats Blocked</div>
        <div className="stat-value" style={{ color: 'var(--threat-block)' }}>
          {blocked}
          <span className="stat-meta">({blockRate}%)</span>
        </div>
        <div className="stat-meta">Zero false negatives allowed</div>
      </div>

      <div className="stat-card stat-approved">
        <div className="stat-label">Verified & Approved</div>
        <div className="stat-value" style={{ color: 'var(--threat-approve)' }}>
          {approved}
        </div>
        <div className="stat-meta">Clean intent & params</div>
      </div>

      <div className="stat-card stat-risk">
        <div className="stat-label">Average Risk Index</div>
        <div className="stat-value" style={{ color: 'var(--cyan-neon)' }}>
          {avgScore}
          <span className="stat-meta">/100</span>
        </div>
        <div className="stat-meta">Telemetry composite score</div>
      </div>

      <div className="stat-card">
        <div className="stat-label">Mock Checking Balance</div>
        <div className="stat-value" style={{ color: '#fff' }}>
          ${checkingAcc ? checkingAcc.balance.toLocaleString('en-US', { minimumFractionDigits: 2 }) : '4,250.00'}
        </div>
        <div className="stat-meta">Protected mock ledger</div>
      </div>
    </div>
  );
};
