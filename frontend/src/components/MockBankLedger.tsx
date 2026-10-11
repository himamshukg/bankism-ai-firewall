import React from 'react';
import type { AccountInfo, TransactionRecord } from '../types';

interface MockBankLedgerProps {
  accounts: AccountInfo[];
  transactions: TransactionRecord[];
}

export const MockBankLedger: React.FC<MockBankLedgerProps> = ({ accounts, transactions }) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
        Mock in-memory financial ledger. Bankism AI Firewall guarantees this core ledger is never connected to real banking systems, and is strictly isolated from blocked or unauthorized requests.
      </div>

      {/* Account Balances */}
      <div className="ledger-grid">
        {accounts.map((acc) => (
          <div key={acc.account_id} className="account-card">
            <div className="acc-title">{acc.account_name}</div>
            <div className="acc-number">{acc.account_number}</div>
            <div className="acc-balance">
              ${acc.balance.toLocaleString('en-US', { minimumFractionDigits: 2 })} {acc.currency}
            </div>
          </div>
        ))}
      </div>

      {/* Transactions Ledger */}
      <div>
        <div className="field-label" style={{ marginBottom: '0.5rem' }}>
          Simulated Settlement History ({transactions.length} Records)
        </div>
        <div className="audit-table-wrapper">
          <table className="audit-table">
            <thead>
              <tr>
                <th>Tx ID</th>
                <th>Type</th>
                <th>Amount</th>
                <th>Recipient / Source</th>
                <th>Memo</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {transactions.map((tx) => (
                <tr key={tx.id}>
                  <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan-neon)', fontSize: '0.75rem' }}>
                    {tx.id}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>{tx.type}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#fff' }}>
                    ${tx.amount.toLocaleString('en-US', { minimumFractionDigits: 2 })}
                  </td>
                  <td>{tx.recipient || tx.source_account}</td>
                  <td style={{ fontStyle: tx.memo ? 'normal' : 'italic' }}>{tx.memo || 'None'}</td>
                  <td>
                    <span className="badge-status-pill approve">{tx.status}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
