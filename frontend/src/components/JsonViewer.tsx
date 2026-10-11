import React, { useState } from 'react';
import type { ScanResult } from '../types';

interface JsonViewerProps {
  data: ScanResult | null;
}

export const JsonViewer: React.FC<JsonViewerProps> = ({ data }) => {
  const [copied, setCopied] = useState(false);

  if (!data) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-faint)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
        No scan payload available. Execute a scan to inspect raw firewall telemetry JSON.
      </div>
    );
  }

  const jsonString = JSON.stringify(data, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="json-viewer-box">
      <button className="json-copy-btn" onClick={handleCopy}>
        {copied ? '✓ Copied to Clipboard' : 'Copy JSON'}
      </button>
      <pre className="json-code">{jsonString}</pre>
    </div>
  );
};
