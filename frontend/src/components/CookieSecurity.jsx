import React, { useState } from 'react';
import SecurityExplanation from './SecurityExplanation';

const CookieTable = ({ cookies }) => {
  const [selectedIssue, setSelectedIssue] = useState(null);

  if (!cookies || cookies.length === 0) {
    return <p className="subtitle" style={{ fontSize: '0.9rem', marginTop: '1rem' }}>No cookies detected during scan.</p>;
  }

  return (
    <>
      <div className="cookie-table-wrapper fadeIn">
        <table className="cookie-table">
          <thead>
            <tr>
              <th>Cookie Name</th>
              <th>Value</th>
              <th>Secure</th>
              <th>HttpOnly</th>
              <th>SameSite</th>
              <th>Risk</th>
              <th>Issues</th>
            </tr>
          </thead>
          <tbody>
            {cookies.map((cookie, idx) => (
              <tr key={idx}>
                <td className="cookie-name-cell">{cookie.name}</td>
                <td className="cookie-val-cell" title={cookie.value}>{cookie.value}</td>
                <td>
                  <span className={`flag-badge ${cookie.secure ? 'active' : 'inactive'}`}>
                    {cookie.secure ? '🔒' : '🔓'}
                  </span>
                </td>
                <td>
                  <span className={`flag-badge ${cookie.httpOnly ? 'active' : 'inactive'}`}>
                    {cookie.httpOnly ? '✅' : '❌'}
                  </span>
                </td>
                <td>
                  <span className="status-badge" style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)' }}>
                    {cookie.sameSite}
                  </span>
                </td>
                <td>
                  <span className={`risk-pill risk-${cookie.risk.toLowerCase()}`}>
                    {cookie.risk}
                  </span>
                </td>
                <td className="issues-cell">
                  {cookie.humanIssues && cookie.humanIssues.length > 0 ? (
                    <ul>
                      {cookie.humanIssues.map((issue, i) => (
                        <li key={i} className="issue-item">
                          <span className="issue-bullet">•</span>
                          <span className="issue-text">{issue.details.title}</span>
                          <button 
                            className="learn-more-btn"
                            onClick={() => setSelectedIssue(issue)}
                          >
                            Learn More
                          </button>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <span className="status-badge success" style={{ fontSize: '0.7rem' }}>Secure</span>
                  )}
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
    </>
  );
};

const CookieSecurity = ({ cookieSecurity }) => {
  return (
    <div className="result-card glass-panel cookie-security-card">
      <div className="result-header">
        <span className="category-icon">🍪</span>
        <h3 className="result-title">Cookie Security Analysis</h3>
      </div>
      <CookieTable cookies={cookieSecurity} />
    </div>
  );
};

export default CookieSecurity;
