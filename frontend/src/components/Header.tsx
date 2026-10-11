import React from 'react';

interface HeaderProps {
  onReset: () => void;
  resetting: boolean;
}

export const Header: React.FC<HeaderProps> = ({ onReset, resetting }) => {
  return (
    <header className="header-container">
      <div className="header-content">
        <div className="brand-section">
          <div className="brand-icon-shield">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              <path d="m9 12 2 2 4-4"></path>
            </svg>
          </div>
          <div>
            <h1 className="brand-title">BANKISM</h1>
            <div className="brand-subtitle">Blue-Team AI Firewall // Financial LLM Defense</div>
          </div>
        </div>

        <div className="header-badges">
          <div className="badge-telemetry">
            <span className="status-dot"></span>
            <span>FAIL-CLOSED ACTIVE</span>
          </div>

          <div className="badge-telemetry">
            <span>RULESET: v1.0.4-PROD</span>
          </div>

          <button 
            className="btn-reset" 
            onClick={onReset} 
            disabled={resetting}
            title="Reset mock accounts and scan history"
          >
            {resetting ? 'Resetting...' : 'Reset Mock Ledger'}
          </button>
        </div>
      </div>
    </header>
  );
};
