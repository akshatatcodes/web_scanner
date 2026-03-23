import React, { useState } from 'react';
import SecurityExplanation from './SecurityExplanation';

const SuspiciousScripts = ({ scripts }) => {
  const [selectedIssue, setSelectedIssue] = useState(null);

  const safeScripts = scripts || [];

  // Group scripts into Protection, Indicators, and Threat Intelligence
  const protectionFindings = safeScripts.filter(s => s.source === 'HTTP Headers');
  const exposureIndicators = safeScripts.filter(s => !['HTTP Headers', 'Google Safe Browsing'].includes(s.source));
  const blacklistFindings = safeScripts.filter(s => s.source === 'Google Safe Browsing');

  const getRiskClass = (risk) => {
    switch (risk?.toUpperCase()) {
      case 'HIGH': return 'risk-high';
      case 'MEDIUM': return 'risk-medium';
      case 'LOW': return 'risk-low';
      default: return '';
    }
  };

  const renderScriptSource = (source) => {
    if (source === 'inline-script') return <span className="source-inline">[Inline Script]</span>;
    if (source === 'HTTP Headers') return <span className="source-header">Security Headers</span>;
    if (source === 'Google Safe Browsing') return <span className="source-header">Threat Intelligence</span>;
    return <span className="source-url" title={source}>{source.length > 50 ? source.substring(0, 47) + '...' : source}</span>;
  };

  return (
    <div className="glass-panel result-card xss-card full-width fadeIn">
      <div className="result-header">
        <span className="category-icon">🛡️</span>
        <h3 className="result-title">Security & Risk Analysis</h3>
      </div>
      
      <div className="xss-analysis-grid">
        {/* XSS Exposure Indicators */}
        <div className="xss-section">
          <h4 className="xss-section-title">XSS Exposure Indicators</h4>
          {exposureIndicators.length === 0 ? (
            <p className="no-findings">No dangerous JS patterns detected.</p>
          ) : (
            <div className="xss-findings-list">
              {exposureIndicators.map((script, idx) => (
                <div key={idx} className="xss-finding-item">
                  <div className="finding-source">
                    {renderScriptSource(script.source)}
                    <span className={`risk-pill small ${getRiskClass(script.risk)}`}>{script.risk}</span>
                  </div>
                  <ul className="finding-issues">
                    {script.humanIssues.map((issue, iidx) => (
                      <li key={iidx} className="issue-row">
                        <div className="issue-main">
                          <span className="issue-title">⚠️ {issue.details.title}</span>
                          {issue.line && <span className="issue-line">Line: {issue.line}</span>}
                        </div>
                        <button 
                          className="learn-more-link"
                          onClick={() => setSelectedIssue(issue)}
                        >
                          Details
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Security Protection */}
        <div className="xss-section divider-left">
          <h4 className="xss-section-title">Security Protection</h4>
          <div className="xss-findings-list">
            {protectionFindings.length === 0 ? (
              <div className="protection-item pos">
                <span className="prot-icon">✅</span>
                <span className="prot-text">Content Security Policy Detected</span>
              </div>
            ) : (
              protectionFindings.flatMap(s => s.humanIssues).map((issue, idx) => (
                <div key={idx} className="protection-item neg">
                  <span className="prot-icon">❌</span>
                  <div className="prot-content">
                    <span className="prot-text">{issue.details.title}</span>
                    <button 
                      className="learn-more-link"
                      onClick={() => setSelectedIssue(issue)}
                    >
                      How to fix
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Threat Intelligence (Google Safe Browsing) */}
          <h4 className="xss-section-title" style={{ marginTop: '2rem' }}>Threat Intelligence</h4>
          <div className="xss-findings-list">
            {blacklistFindings.length === 0 ? (
              <div className="protection-item pos">
                <span className="prot-icon">🔍</span>
                <span className="prot-text">Not listed in known threat databases</span>
              </div>
            ) : (
              blacklistFindings.map((finding, idx) => (
                <div key={idx} className="protection-item neg">
                  <span className="prot-icon">⚠️</span>
                  <div className="prot-content">
                    <span className="prot-text" style={{ color: 'var(--danger)' }}>
                       {finding.humanIssues[0].details.title}
                    </span>
                    <p style={{ fontSize: '0.8rem', opacity: 0.8, margin: '0.25rem 0' }}>
                      {finding.humanIssues[0].reason}
                    </p>
                    <button 
                      className="learn-more-link"
                      onClick={() => setSelectedIssue(finding.humanIssues[0])}
                    >
                      View details
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {selectedIssue && (
        <SecurityExplanation 
          issue={selectedIssue} 
          onClose={() => setSelectedIssue(null)} 
        />
      )}
    </div>
  );
};

export default SuspiciousScripts;
