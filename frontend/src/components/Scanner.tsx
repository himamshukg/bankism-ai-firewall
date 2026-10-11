import React from 'react';
import type { SampleRequest } from '../types';

interface ScannerProps {
  prompt: string;
  setPrompt: (val: string) => void;
  samples: SampleRequest[];
  onScan: () => void;
  loading: boolean;
  executeAction: boolean;
  setExecuteAction: (val: boolean) => void;
}

export const Scanner: React.FC<ScannerProps> = ({
  prompt,
  setPrompt,
  samples,
  onScan,
  loading,
  executeAction,
  setExecuteAction,
}) => {
  const handleSelectSample = (sample: SampleRequest) => {
    setPrompt(sample.prompt);
  };

  const getTagClass = (category: string) => {
    if (category === 'BENIGN') return 'tag-benign';
    if (category === 'AMBIGUOUS' || category === 'MALFORMED_AMOUNT') return 'tag-boundary';
    return 'tag-attack';
  };

  return (
    <div className="glass-panel scanner-card">
      <div className="section-header">
        <div>
          <div className="section-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            Natural-Language Request Scanner
          </div>
          <div className="section-sub">
            Submits raw unstructured banking prompts to the deterministic AI Firewall.
          </div>
        </div>
      </div>

      {/* Preset Vectors */}
      <div className="presets-container">
        <div className="presets-label">Prompt Test Vectors (Click to load):</div>
        <div className="presets-chips">
          {samples.map((sample) => (
            <button
              key={sample.id}
              className={`preset-chip ${prompt === sample.prompt ? 'active' : ''}`}
              onClick={() => handleSelectSample(sample)}
              title={sample.description}
            >
              <span className={`chip-tag ${getTagClass(sample.category)}`}>
                {sample.expected_decision}
              </span>
              <span>{sample.title}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Input Area */}
      <div className="textarea-wrapper">
        <textarea
          className="scanner-textarea"
          rows={4}
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          placeholder="Enter natural language banking prompt (e.g. 'Transfer $45.50 to Alice for dinner' or prompt injection test vectors)..."
        />
      </div>

      {/* Controls & Actions */}
      <div className="scanner-controls">
        <label className="checkbox-toggle">
          <input
            type="checkbox"
            checked={executeAction}
            onChange={(e) => setExecuteAction(e.target.checked)}
          />
          <span>Execute mock banking action if approved</span>
        </label>

        <div className="btn-group">
          {prompt && (
            <button
              className="btn-secondary"
              onClick={() => setPrompt('')}
              disabled={loading}
            >
              Clear
            </button>
          )}

          <button
            className="btn-primary"
            onClick={onScan}
            disabled={loading || !prompt.trim()}
          >
            {loading ? (
              <>
                <svg className="animate-spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <circle cx="12" cy="12" r="10" strokeDasharray="32" strokeDashoffset="12"></circle>
                </svg>
                Analyzing...
              </>
            ) : (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polygon points="5 3 19 12 5 21 5 3"></polygon>
                </svg>
                Scan & Evaluate
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
