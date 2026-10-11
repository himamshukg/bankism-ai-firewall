import React from 'react';
import type { ScanResult } from '../types';

interface VerdictCardProps {
  result: ScanResult | null;
}

export const VerdictCard: React.FC<VerdictCardProps> = ({ result }) => {
  if (!result) {
    return (
      <div className="glass-panel verdict-card" style={{ justifyContent: 'center', alignItems: 'center', minHeight: '380px' }}>
        <div style={{ textAlign: 'center', color: 'var(--text-faint)', maxWidth: '320px' }}>
          <div style={{ fontSize: '3rem', marginBottom: '1rem', opacity: 0.5 }}>🛡️</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--cyan-neon)', marginBottom: '0.4rem' }}>
            AWAITING INBOUND REQUEST
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Select a sample vector or type a banking prompt on the left to evaluate the AI firewall.
          </div>
        </div>
      </div>
    );
  }

  const isApproved = result.decision === 'APPROVE';

  const getRiskColor = (score: number) => {
    if (score >= 85) return 'var(--risk-crit)';
    if (score >= 60) return 'var(--risk-high)';
    if (score >= 30) return 'var(--risk-med)';
    return 'var(--risk-low)';
  };

  const riskColor = getRiskColor(result.risk_score);
  const parsed = result.parsed_request;

  return (
    <div className="glass-panel verdict-card">
      {/* Top Banner */}
      <div className={`verdict-banner ${isApproved ? 'verdict-approve' : 'verdict-block'}`}>
        <div className="verdict-main">
          <div className="verdict-icon">
            {isApproved ? (
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <path d="m9 12 2 2 4-4"></path>
              </svg>
            ) : (
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <line x1="15" y1="9" x2="9" y2="15"></line>
                <line x1="9" y1="9" x2="15" y2="15"></line>
              </svg>
            )}
          </div>
          <div>
            <div className="verdict-title">{result.decision}</div>
            <div className="verdict-subtitle">
              {isApproved ? 'VERIFIED SAFE // DETERMINISTIC APPROVAL' : 'THREAT MITIGATED // FAIL-CLOSED ENFORCEMENT'}
            </div>
          </div>
        </div>

        {/* Risk meter */}
        <div className="risk-meter-container">
          <div className="risk-score-value" style={{ color: riskColor }}>
            {result.risk_score}
            <span style={{ fontSize: '0.85rem', color: 'var(--text-faint)' }}> /100</span>
          </div>
          <div 
            className="risk-level-badge" 
            style={{ 
              backgroundColor: `${riskColor}22`, 
              color: riskColor,
              border: `1px solid ${riskColor}66`
            }}
          >
            {result.risk_level} RISK
          </div>
          <div className="risk-bar-track">
            <div 
              className="risk-bar-fill" 
              style={{ width: `${result.risk_score}%`, backgroundColor: riskColor }}
            />
          </div>
        </div>
      </div>

      {/* Threats detected */}
      <div>
        <div className="field-label" style={{ marginBottom: '0.4rem' }}>
          Identified Threat Categories
        </div>
        <div className="threat-tags-list">
          {result.threat_categories.length > 0 ? (
            result.threat_categories.map((t) => (
              <span key={t} className="threat-tag">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path>
                  <line x1="12" y1="9" x2="12" y2="13"></line>
                  <line x1="12" y1="17" x2="12.01" y2="17"></line>
                </svg>
                {t}
              </span>
            ))
          ) : (
            <span className="threat-tag none">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <polyline points="20 6 9 17 4 12"></polyline>
              </svg>
              NONE DETECTED (CLEAN SPECIFICATION)
            </span>
          )}
        </div>
      </div>

      {/* Rationale */}
      <div className="rationale-box">
        <div className="rationale-title">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="16" x2="12" y2="12"></line>
            <line x1="12" y1="8" x2="12.01" y2="8"></line>
          </svg>
          Security Rationale & Forensic Breakdown
        </div>
        <div className="rationale-text">{result.rationale}</div>
      </div>

      {/* Parsed Banking Parameters */}
      {parsed && (
        <div className="parsed-details-grid">
          <div className="parsed-field">
            <div className="field-label">Banking Action Intent</div>
            <div className="field-value highlight-green">{parsed.intent}</div>
          </div>

          <div className="parsed-field">
            <div className="field-label">Validated Amount</div>
            <div className={`field-value ${parsed.amount !== null && parsed.amount > 0 ? 'highlight-green' : 'highlight-red'}`}>
              {parsed.amount !== null ? `$${parsed.amount.toLocaleString('en-US', { minimumFractionDigits: 2 })} ${parsed.currency}` : 'NONE / UNPARSEABLE'}
            </div>
          </div>

          <div className="parsed-field">
            <div className="field-label">Target Recipient</div>
            <div className="field-value">{parsed.recipient || 'N/A (INQUIRY / MISSING)'}</div>
          </div>

          <div className="parsed-field">
            <div className="field-label">Sanitized Memo Payload</div>
            <div className="field-value" style={{ fontSize: '0.8rem', fontStyle: parsed.memo ? 'normal' : 'italic' }}>
              {parsed.memo || 'None'}
            </div>
          </div>
        </div>
      )}

      {/* Simulator Execution Status */}
      {result.execution_receipt && (
        <div className={`simulation-card ${result.execution_receipt.success ? 'sim-success' : 'sim-blocked'}`}>
          <div className="sim-header">
            <div className="sim-title">
              {result.execution_receipt.success ? (
                <>
                  <span style={{ color: 'var(--threat-approve)' }}>✓</span>
                  <span>Mock Banking Action Executed</span>
                </>
              ) : (
                <>
                  <span style={{ color: 'var(--threat-block)' }}>✕</span>
                  <span>Mock Action Strictly Refused</span>
                </>
              )}
            </div>
            {result.execution_receipt.transaction_id && (
              <div className="sim-txid">{result.execution_receipt.transaction_id}</div>
            )}
          </div>
          <div className="sim-message">{result.execution_receipt.message}</div>
        </div>
      )}
    </div>
  );
};
