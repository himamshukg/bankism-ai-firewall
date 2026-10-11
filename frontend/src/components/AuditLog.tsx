import React from 'react';
import type { ScanResult } from '../types';

interface AuditLogProps {
  history: ScanResult[];
  onSelectScan: (scan: ScanResult) => void;
}

export const AuditLog: React.FC<AuditLogProps> = ({ history, onSelectScan }) => {
  if (history.length === 0) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-faint)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
        No scan events recorded yet in this session.
      </div>
    );
  }

  return (
    <div className="audit-table-wrapper">
      <table className="audit-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Scan ID</th>
            <th>Prompt Preview</th>
            <th>Verdict</th>
            <th>Risk Score</th>
            <th>Threats Flagged</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {history.map((item) => {
            const timeFormatted = new Date(item.timestamp).toLocaleTimeString();
            return (
              <tr key={item.scan_id}>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>{timeFormatted}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--cyan-neon)' }}>
                  {item.scan_id}
                </td>
                <td style={{ maxWidth: '320px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {item.prompt}
                </td>
                <td>
                  <span className={`badge-status-pill ${item.decision === 'APPROVE' ? 'approve' : 'block'}`}>
                    {item.decision}
                  </span>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                  {item.risk_score}/100
                </td>
                <td>
                  {item.threat_categories.length > 0 ? (
                    <span style={{ color: 'var(--threat-block)', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                      {item.threat_categories.join(', ')}
                    </span>
                  ) : (
                    <span style={{ color: 'var(--threat-approve)', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                      Clean
                    </span>
                  )}
                </td>
                <td>
                  <button
                    className="btn-secondary"
                    style={{ padding: '0.2rem 0.6rem', fontSize: '0.72rem' }}
                    onClick={() => onSelectScan(item)}
                  >
                    Inspect
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
