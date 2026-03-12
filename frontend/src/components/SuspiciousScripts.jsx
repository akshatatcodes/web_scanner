import React, { useState } from 'react';
import SecurityExplanation from './SecurityExplanation';

const SuspiciousScripts = ({ scripts }) => {
  const [selectedIssue, setSelectedIssue] = useState(null);

  if (!scripts || scripts.length === 0) return null;

  const getRiskClass = (risk) => {
    switch (risk) {
      case 'HIGH': return 'risk-high';
      case 'MEDIUM': return 'risk-medium';
      case 'LOW': return 'risk-low';
      default: return '';
    }
  };

  return (
    <div className="glass-panel result-card vulnerabilities-card full-width fadeIn">
      <div className="result-header">
        <span className="category-icon">🛡️</span>
        <h3 className="result-title">Suspicious Script Detection</h3>
      </div>
      
      <div className="cookie-table-wrapper">
        <table className="cookie-table">
          <thead>
            <tr>
              <th>Script Source</th>
              <th>Risk Level</th>
              <th>Security Issues</th>
            </tr>
          </thead>
          <tbody>
            {scripts.map((script, idx) => (
              <tr key={idx}>
                <td className="cookie-val-cell" title={script.source}>
                  {script.source === 'inline-script' ? (
                    <span style={{ color: 'var(--accent-secondary)', fontWeight: 600 }}>[Inline Script]</span>
                  ) : script.source}
                </td>
                <td>
                  <span className={`risk-pill ${getRiskClass(script.risk)}`}>
                    {script.risk}
                  </span>
                </td>
                <td className="issues-cell">
                  <ul>
                    {script.humanIssues.map((issue, iidx) => (
                      <li key={iidx} className="issue-item">
                        <span className="issue-bullet">!</span>
                        <div className="issue-text">
                          {issue.details.title}
                          <button 
                            className="learn-more-btn"
                            onClick={() => setSelectedIssue(issue)}
                          >
                            Learn More
                          </button>
                        </div>
                      </li>
                    ))}
                  </ul>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
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
