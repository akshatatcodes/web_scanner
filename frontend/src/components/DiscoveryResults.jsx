import React, { useState } from 'react';
import SecurityExplanation from './SecurityExplanation';
import CrawlerInsights from './CrawlerInsights';
import ProofModal from './ProofModal';

const EXPLOIT_DETAILS = {
  SQL_INJECTION: {
    title: "SQL Injection (SQLi)",
    explanation: "The application fails to properly sanitize user input before using it in a database query.",
    impact: "Allows attackers to bypass authentication and read or delete sensitive data.",
    recommendation: "Use parameterized queries (prepared statements) to prevent injection."
  },
  COMMAND_INJECTION: {
    title: "OS Command Injection",
    explanation: "The web application passes unvalidated user input to the operating system's command shell.",
    impact: "Allows attackers to execute arbitrary system commands, potentially leading to full server takeover.",
    recommendation: "Avoid calling system commands directly; use language-specific APIs instead."
  },
  IDOR_VULNERABILITY: {
    title: "Insecure Direct Object Reference (IDOR)",
    explanation: "The application reveals direct access to objects in the URL without checking authorization.",
    impact: "Users can view or modify other people's private data by changing IDs in the URL.",
    recommendation: "Implement strict access control checks for every object request."
  },
  JWT_MISCONFIG: {
    title: "JWT Security Misconfiguration",
    explanation: "The JSON Web Token (JWT) is either poorly signed or contains sensitive data.",
    impact: "Allows attackers to forge tokens or steal session info, leading to unauthorized access.",
    recommendation: "Use strong signing (RS256) and never put PII in a JWT payload."
  }
};

const DiscoveryResults = ({ 
  adminPanels = [], 
  hiddenEndpoints = [], 
  secretLeaks = [],
  directories = [],
  corsIssues = [],
  graphqlFindings = [],
  openRedirects = [],
  ssrfFindings = [],
  authBypasses = [],
  rateLimits = [],
  sqli = [],
  cmdInjection = [],
  idors = [],
  jwtIssues = [],
  scanContext = null,
  waf = null
}) => {
  const [selectedIssue, setSelectedIssue] = useState(null);
  const [selectedProof, setSelectedProof] = useState(null);

  // Categorize JWT issues natively
  const jwtCritical = jwtIssues.filter(j => j.severity === 'CRITICAL');
  const jwtHigh = jwtIssues.filter(j => j.severity === 'HIGH');
  const jwtMediumLow = jwtIssues.filter(j => ['MEDIUM', 'LOW', 'INFO'].includes(j.severity?.toUpperCase()));

  const hasCritical = sqli.length > 0 || cmdInjection.length > 0 || jwtCritical.length > 0;
  const hasHighRisk = authBypasses.length > 0 || secretLeaks.length > 0 || adminPanels.length > 0 || idors.length > 0 || jwtHigh.length > 0;
  const hasMediumRisk = corsIssues.length > 0 || graphqlFindings.length > 0 || openRedirects.length > 0 || jwtMediumLow.length > 0;
  const hasInfo = rateLimits.length > 0 || ssrfFindings.length > 0 || hiddenEndpoints.length > 0 || directories.length > 0;
  const hasDiscovery = scanContext && scanContext.endpoints?.length > 0;
  const hasWaf = waf && waf.detected;

  if (!hasCritical && !hasHighRisk && !hasMediumRisk && !hasInfo && !hasDiscovery && !hasWaf) return null;

  const getRiskClass = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'risk-high'; // Red
      case 'HIGH': return 'risk-high'; // Red
      case 'MEDIUM': return 'risk-medium'; // Orange
      case 'LOW':
      case 'INFO': return 'risk-low'; // Blue
      default: return '';
    }
  };

  const renderConfidence = (conf) => {
      if (!conf) return null;
      let clr = '#9ca3af';
      if (conf === 'Confirmed') clr = '#ef4444';
      else if (conf === 'High Probability') clr = '#f59e0b';
      return <span style={{ fontSize: '0.75rem', fontWeight: '600', color: clr, border: `1px solid ${clr}`, padding: '0.1rem 0.4rem', borderRadius: '4px', marginLeft: '0.5rem' }}>{conf}</span>;
  };

  return (
    <div className="discovery-wrapper full-width fadeIn">
      <div className="glass-panel result-card discovery-card" style={{ marginBottom: '1.5rem', background: 'rgba(0,0,0,0.3)' }}>
        <div className="result-header" style={{ marginBottom: '2rem' }}>
          <span className="category-icon">🛡️</span>
          <h3 className="result-title">Active Exploitation & Vulnerability Analysis</h3>
        </div>

        {/* ELITE Crawler Insights */}
        {scanContext && <CrawlerInsights scanContext={scanContext} />}

        {/* WAF Detection & Evasion Status */}
        {waf && waf.detected && (
          <div className="risk-section waf-dashboard" style={{ marginBottom: '2.5rem' }}>
            <h4 style={{ color: '#8b5cf6', borderBottom: '1px solid rgba(139, 92, 246, 0.4)', paddingBottom: '0.8rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.8rem' }}>
              <span style={{ fontSize: '1.4rem' }}>🛡️</span> Defense Infrastructure
            </h4>
            <div className="glass-panel" style={{ background: 'rgba(139, 92, 246, 0.05)', border: '1px solid rgba(139, 92, 246, 0.2)', padding: '1.5rem', borderRadius: '12px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
                <div className="waf-stat">
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginBottom: '0.4rem' }}>PROTECTOR</div>
                  <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#a78bfa' }}>{waf.name}</div>
                </div>
                <div className="waf-stat">
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginBottom: '0.4rem' }}>CONFIDENCE</div>
                  <div style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{(waf.confidence * 100).toFixed(0)}%</div>
                </div>
                <div className="waf-stat">
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginBottom: '0.4rem' }}>EVASION STRATEGY</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ color: '#10b981', fontSize: '1.2rem' }}>⚡</span>
                    <span style={{ fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', color: '#10b981' }}>{waf.evasionStrategy?.replace('_', ' ') || 'ACTIVE'}</span>
                  </div>
                </div>
              </div>
              
              <div style={{ marginTop: '1.5rem', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '1rem' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>DETECTED SIGNALS</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                  {waf.signals?.map((sig, i) => (
                    <span key={i} style={{ background: 'rgba(255,255,255,0.05)', padding: '0.2rem 0.6rem', borderRadius: '4px', fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                      {sig}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* CRITICAL SECTION */}
        {hasCritical && (
          <div className="risk-section" style={{ marginBottom: '2.5rem' }}>
            <h4 style={{ color: '#dc2626', borderBottom: '1px solid rgba(220, 38, 38, 0.4)', paddingBottom: '0.8rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.8rem', textShadow: '0 0 10px rgba(220,38,38,0.5)' }}>
              <span style={{ fontSize: '1.4rem' }}>💥</span> Critical Exploitations
            </h4>
            <div className="discovery-grid">
              
              {sqli.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #dc2626', background: 'rgba(220,38,38,0.05)' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">💉</span> SQL Injection</h4>
                  <div className="discovery-list">
                    {sqli.map((issue, idx) => (
                      <div key={idx} className="discovery-item secret-item">
                        <div className="secret-header">
                          <span className="secret-source">Param: {issue.parameter} {renderConfidence(issue.confidence)}</span>
                          <span className={`risk-pill small ${getRiskClass(issue.severity)}`}>{issue.severity}</span>
                        </div>
                        <div className="secret-matches">
                          <div className="secret-match-code">{issue.message}</div>
                          {issue.url && <div className="url-text" style={{fontSize:'0.75rem', marginTop:'0.3rem'}}>{issue.url}</div>}
                          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.8rem', flexWrap: 'wrap' }}>
                            <button 
                              className="learn-more-btn" 
                              style={{fontSize: '0.7rem', opacity: 0.8}}
                              onClick={() => setSelectedIssue({ details: EXPLOIT_DETAILS.SQL_INJECTION })}
                            >
                              What is this?
                            </button>
                            {issue.proof && (
                              <button
                                className="learn-more-btn"
                                style={{ fontSize: '0.7rem', background: 'rgba(239,68,68,0.15)', borderColor: 'rgba(239,68,68,0.4)', color: '#f87171' }}
                                onClick={() => setSelectedProof(issue.proof)}
                              >🧪 View Proof</button>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {cmdInjection.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #dc2626', background: 'rgba(220,38,38,0.05)' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">⌨️</span> Command Injection</h4>
                  <div className="discovery-list">
                    {cmdInjection.map((issue, idx) => (
                      <div key={idx} className="discovery-item secret-item">
                        <div className="secret-header">
                          <span className="secret-source">Param: {issue.parameter} {renderConfidence(issue.confidence)}</span>
                          <span className={`risk-pill small ${getRiskClass(issue.severity)}`}>{issue.severity}</span>
                        </div>
                        <div className="secret-matches">
                          <div className="secret-match-code">{issue.message}</div>
                          {issue.url && <div className="url-text" style={{fontSize:'0.75rem', marginTop:'0.3rem'}}>{issue.url}</div>}
                          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.8rem', flexWrap: 'wrap' }}>
                            <button 
                              className="learn-more-btn" 
                              style={{fontSize: '0.7rem', opacity: 0.8}}
                              onClick={() => setSelectedIssue({ details: EXPLOIT_DETAILS.COMMAND_INJECTION })}
                            >
                              What is this?
                            </button>
                            {issue.proof && (
                              <button
                                className="learn-more-btn"
                                style={{ fontSize: '0.7rem', background: 'rgba(239,68,68,0.15)', borderColor: 'rgba(239,68,68,0.4)', color: '#f87171' }}
                                onClick={() => setSelectedProof(issue.proof)}
                              >🧪 View Proof</button>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {jwtCritical.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #dc2626', background: 'rgba(220,38,38,0.05)' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">🎫</span> Critical JWT Bypass</h4>
                  <div className="discovery-list">
                    {jwtCritical.map((issue, idx) => (
                      <div key={idx} className="discovery-item secret-item">
                        <div className="secret-header">
                          <span className="secret-source">JSON Web Token {renderConfidence(issue.confidence)}</span>
                          <span className={`risk-pill small ${getRiskClass(issue.severity)}`}>{issue.severity}</span>
                        </div>
                        <div className="secret-matches">
                          <div className="secret-match-code">{issue.message}</div>
                          <div className="url-text" style={{fontSize:'0.75rem', marginTop:'0.3rem'}}>{issue.evidence}</div>
                          <button 
                            className="learn-more-btn" 
                            style={{marginTop: '0.8rem', fontSize: '0.7rem', opacity: 0.8}}
                            onClick={() => setSelectedIssue({ details: EXPLOIT_DETAILS.JWT_MISCONFIG })}
                          >
                            What is this?
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </div>
          </div>
        )}

        {/* HIGH RISK SECTION */}
        {hasHighRisk && (
          <div className="risk-section" style={{ marginBottom: '2.5rem' }}>
            <h4 style={{ color: '#ef4444', borderBottom: '1px solid rgba(239, 68, 68, 0.3)', paddingBottom: '0.8rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.8rem' }}>
              <span style={{ fontSize: '1.3rem' }}>🚨</span> High Risk
            </h4>
            <div className="discovery-grid">
              
              {idors.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #ef4444' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">🪪</span> IDOR Vectors</h4>
                  <div className="discovery-list">
                    {idors.map((issue, idx) => (
                      <div key={idx} className="discovery-item secret-item">
                        <div className="secret-header">
                          <span className="secret-source">Param: {issue.parameter} {renderConfidence(issue.confidence)}</span>
                          <span className={`risk-pill small ${getRiskClass(issue.severity)}`}>{issue.severity}</span>
                        </div>
                        <div className="secret-matches">
                          <div className="secret-match-code">{issue.message}</div>
                          {issue.url && <div className="url-text" style={{fontSize:'0.75rem', marginTop:'0.3rem'}}>{issue.url}</div>}
                          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.8rem', flexWrap: 'wrap' }}>
                            <button 
                              className="learn-more-btn" 
                              style={{fontSize: '0.7rem', opacity: 0.8}}
                              onClick={() => setSelectedIssue({ details: EXPLOIT_DETAILS.IDOR_VULNERABILITY })}
                            >
                              What is this?
                            </button>
                            {issue.proof && (
                              <button
                                className="learn-more-btn"
                                style={{ fontSize: '0.7rem', background: 'rgba(239,68,68,0.15)', borderColor: 'rgba(239,68,68,0.4)', color: '#f87171' }}
                                onClick={() => setSelectedProof(issue.proof)}
                              >🧪 View Proof</button>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {authBypasses.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #ef4444' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">🔓</span> Auth Bypass</h4>
                  <div className="discovery-list">
                    {authBypasses.map((issue, idx) => (
                      <div key={idx} className="discovery-item secret-item">
                        <div className="secret-header">
                          <span className="secret-source url-text">Endpoint Bypass</span>
                          <span className={`risk-pill small ${getRiskClass(issue.severity)}`}>{issue.severity}</span>
                        </div>
                        <div className="secret-matches">
                          <div className="secret-match-code">{issue.message}</div>
                          <div className="url-text" style={{fontSize:'0.75rem', marginTop:'0.3rem'}}>{issue.url}</div>
                          {issue.proof && (
                            <button
                              className="learn-more-btn"
                              style={{ marginTop: '0.6rem', fontSize: '0.7rem', background: 'rgba(239,68,68,0.15)', borderColor: 'rgba(239,68,68,0.4)', color: '#f87171' }}
                              onClick={() => setSelectedProof(issue.proof)}
                            >🧪 View Proof</button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {jwtHigh.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #ef4444' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">🎫</span> JWT Vulnerability</h4>
                  <div className="discovery-list">
                    {jwtHigh.map((issue, idx) => (
                       <div key={idx} className="discovery-item secret-item">
                       <div className="secret-header">
                         <span className="secret-source">Misconfiguration {renderConfidence(issue.confidence)}</span>
                         <span className={`risk-pill small ${getRiskClass(issue.severity)}`}>{issue.severity}</span>
                       </div>
                       <div className="secret-matches">
                         <div className="secret-match-code">{issue.message}</div>
                       </div>
                     </div>
                    ))}
                  </div>
                </div>
              )}

              {secretLeaks.length > 0 && (
                <div className="discovery-section secret-section" style={{ borderLeft: '3px solid #ef4444' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">🔑</span> Secret Leaks Detected</h4>
                  <div className="discovery-list">
                    {secretLeaks.map((secret, idx) => (
                      <div key={idx} className="discovery-item secret-item">
                        <div className="secret-header">
                          <span className="secret-source" title={secret.source}>Source: {secret.source.split('/').pop()}</span>
                          <span className={`risk-pill small ${getRiskClass(secret.severity)}`}>{secret.severity}</span>
                        </div>
                        <div className="secret-matches">
                          {secret.matches.map((match, midx) => (
                            <div key={midx} className="secret-match-code">{match}</div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {adminPanels.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #ef4444' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">🚪</span> Admin Panels Found</h4>
                  <div className="discovery-list">
                    {adminPanels.map((panel, idx) => (
                      <div key={idx} className="discovery-item">
                        <span className="discovery-value url-text">{panel.url}</span>
                        <span className={`risk-pill small ${getRiskClass(panel.severity)}`}>{panel.severity}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </div>
          </div>
        )}

        {/* MEDIUM RISK SECTION */}
        {hasMediumRisk && (
          <div className="risk-section" style={{ marginBottom: '2.5rem' }}>
            <h4 style={{ color: '#f59e0b', borderBottom: '1px solid rgba(245, 158, 11, 0.3)', paddingBottom: '0.8rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.8rem' }}>
              <span style={{ fontSize: '1.3rem' }}>⚠️</span> Medium Risk
            </h4>
            <div className="discovery-grid">

              {corsIssues.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #f59e0b' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">🌐</span> CORS Issues</h4>
                  <div className="discovery-list">
                    {corsIssues.map((issue, idx) => (
                      <div key={idx} className="discovery-item secret-item">
                        <div className="secret-header">
                          <span className="secret-source">{issue.message}</span>
                          <span className={`risk-pill small ${getRiskClass(issue.severity)}`}>{issue.severity}</span>
                        </div>
                        <div className="secret-matches">
                          <div className="secret-match-code">{issue.evidence}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {openRedirects.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #f59e0b' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">↪️</span> Open Redirect</h4>
                  <div className="discovery-list">
                    {openRedirects.map((issue, idx) => (
                      <div key={idx} className="discovery-item secret-item">
                        <div className="secret-header">
                          <span className="secret-source">Parameter: {issue.parameter}</span>
                          <span className={`risk-pill small ${getRiskClass(issue.severity)}`}>{issue.severity}</span>
                        </div>
                        <div className="secret-matches">
                          <div className="secret-match-code">{issue.evidence}</div>
                          {issue.proof && (
                            <button
                              className="learn-more-btn"
                              style={{ marginTop: '0.6rem', fontSize: '0.7rem', background: 'rgba(239,68,68,0.15)', borderColor: 'rgba(239,68,68,0.4)', color: '#f87171' }}
                              onClick={() => setSelectedProof(issue.proof)}
                            >🧪 View Proof</button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {graphqlFindings.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #f59e0b' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">📐</span> GraphQL Exposure</h4>
                  <div className="discovery-list">
                    {graphqlFindings.map((issue, idx) => (
                      <div key={idx} className="discovery-item">
                        <span className="discovery-value url-text">{issue.message}</span>
                        <span className={`risk-pill small ${getRiskClass(issue.severity)}`}>{issue.severity}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {jwtMediumLow.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #f59e0b' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">🎫</span> JWT Weakness</h4>
                  <div className="discovery-list">
                    {jwtMediumLow.map((issue, idx) => (
                      <div key={idx} className="discovery-item secret-item">
                        <div className="secret-header">
                          <span className="secret-source">{issue.message} {renderConfidence(issue.confidence)}</span>
                          <span className={`risk-pill small ${getRiskClass(issue.severity)}`}>{issue.severity}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </div>
          </div>
        )}

        {/* INFO / WEAKNESSES SECTION */}
        {hasInfo && (
          <div className="risk-section">
            <h4 style={{ color: '#3b82f6', borderBottom: '1px solid rgba(59, 130, 246, 0.3)', paddingBottom: '0.8rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.8rem' }}>
              <span style={{ fontSize: '1.3rem' }}>ℹ️</span> Info / Weaknesses
            </h4>
            <div className="discovery-grid">

              {rateLimits.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #3b82f6' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">⏱️</span> Missing Rate Limit</h4>
                  <div className="discovery-list">
                    {rateLimits.map((issue, idx) => (
                      <div key={idx} className="discovery-item">
                        <span className="discovery-value url-text">{issue.message}</span>
                        <span className={`risk-pill small ${getRiskClass(issue.severity)}`}>{issue.severity}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {ssrfFindings.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #3b82f6' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">🔗</span> SSRF Parameters</h4>
                  <div className="discovery-list">
                    {ssrfFindings.map((issue, idx) => (
                      <div key={idx} className="discovery-item secret-item">
                        <div className="secret-header">
                          <span className="discovery-value url-text">?{issue.parameter}=</span>
                          <span className={`risk-pill small ${getRiskClass(issue.severity)}`}>{issue.severity}</span>
                        </div>
                        <div className="secret-matches">
                          <div className="secret-match-code" style={{fontSize:'0.78rem'}}>{issue.message}</div>
                          {issue.proof && (
                            <button
                              className="learn-more-btn"
                              style={{ marginTop: '0.6rem', fontSize: '0.7rem', background: 'rgba(59,130,246,0.12)', borderColor: 'rgba(59,130,246,0.4)', color: '#60a5fa' }}
                              onClick={() => setSelectedProof(issue.proof)}
                            >🧪 View Proof</button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {hiddenEndpoints.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #3b82f6' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">🔌</span> Hidden APIs</h4>
                  <div className="discovery-list endpoints-list">
                    {hiddenEndpoints.map((ep, idx) => (
                      <div key={idx} className="discovery-item endpoint-item">
                        <span className="discovery-value code-text">{ep.endpoint}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {directories.length > 0 && (
                <div className="discovery-section" style={{ borderLeft: '3px solid #3b82f6' }}>
                  <h4 className="discovery-title"><span className="discovery-icon">📁</span> Exposed Directories</h4>
                  <div className="discovery-list">
                    {directories.map((dir, idx) => (
                      <div key={idx} className="discovery-item">
                        <span className="discovery-value url-text">{dir.url}</span>
                        <span className={`risk-pill small ${getRiskClass(dir.severity)}`}>{dir.status}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </div>
          </div>
        )}

      </div>
      {selectedIssue && (
        <SecurityExplanation 
          issue={selectedIssue} 
          onClose={() => setSelectedIssue(null)} 
        />
      )}
      {selectedProof && (
        <ProofModal proof={selectedProof} onClose={() => setSelectedProof(null)} />
      )}
    </div>
  );
};

export default DiscoveryResults;
