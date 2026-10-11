import React from 'react';
import type { SystemStats } from '../types';

interface ThreatStatsProps {
  stats: SystemStats | null;
}

export const ThreatStats: React.FC<ThreatStatsProps> = ({ stats }) => {
  const distribution = stats?.threat_distribution || {};
  const entries = Object.entries(distribution);

  const totalThreats = entries.reduce((acc, [, count]) => acc + count, 0);

  const knownThreats = [
    { key: 'PROMPT_INJECTION', label: 'Prompt Injection / Override' },
    { key: 'JAILBREAK_ATTEMPT', label: 'Persona / DAN Jailbreak' },
    { key: 'MALICIOUS_MEMO', label: 'Malicious Memo / Payload' },
    { key: 'OBFUSCATION_EVASION', label: 'Base64 & Keyword Evasion' },
    { key: 'POLICY_OVERRIDE', label: 'Authority Spoofing' },
    { key: 'SYSTEM_EXTRACTION', label: 'System Prompt Extraction' },
    { key: 'AMBIGUOUS_REQUEST', label: 'Ambiguous / Incomplete Spec' },
    { key: 'MALFORMED_AMOUNT', label: 'Malformed / Boundary Amounts' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
        Real-time telemetry distribution of mitigated threat categories across all evaluated prompts.
      </div>

      <div className="threat-stats-grid">
        {knownThreats.map((t) => {
          const count = distribution[t.key] || 0;
          const percentage = totalThreats > 0 ? Math.round((count / totalThreats) * 100) : 0;
          return (
            <div key={t.key} className="threat-stat-bar-card">
              <div className="threat-bar-title">
                <span>{t.label}</span>
                <span style={{ fontWeight: 700, color: count > 0 ? 'var(--threat-block)' : 'var(--text-faint)' }}>
                  {count}
                </span>
              </div>
              <div className="risk-bar-track">
                <div
                  className="risk-bar-fill"
                  style={{
                    width: `${percentage}%`,
                    backgroundColor: count > 0 ? 'var(--threat-block)' : 'transparent',
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
