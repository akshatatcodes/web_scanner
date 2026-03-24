import { useState } from 'react';
import axios from 'axios';
import './index.css';
import CookieSecurity from './components/CookieSecurity';
import SuspiciousScripts from './components/SuspiciousScripts';
import DomainIntelligence from './components/DomainIntelligence';
import PortScanResults from './components/PortScanResults';

import DiscoveryResults from './components/DiscoveryResults';
import AttackChainView from './components/AttackChainView';
import ReconDashboard from './components/ReconDashboard';
import AttackConsole from './components/AttackConsole';

const API_BASE = import.meta.env.VITE_API_BASE || `http://${window.location.hostname}:5000/api`;

const SearchIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8"></circle>
    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
  </svg>
);

const CategoryIcon = ({ category }) => {
  const icons = {
    'CMS': '📝',
    'Analytics': '📊',
    'Web Frameworks': '⚙️',
    'Frontend Frameworks': '🖼️',
    'CDNs': '🌐',
    'E-commerce': '🛍️',
    'JavaScript Libraries': '📚',
    'Web Servers': '🖥️',
    'Programming Languages': '💻',
    'UI Frameworks': '🎨',
    'Security': '🛡️',
    'Databases': '🗄️',
    'Reverse Proxies': '🔄',
    'Infrastructure': '🏗️',
    'DNS': '📡',
    'Network/Trackers': '🕵️',
    'Cookies/Storage': '🍪',
    'Assets/CDN': '📦',
    'JS Runtime': '🚀'
  };
  return <span className="category-icon">{icons[category] || '📦'}</span>;
};

const getSeverityClass = (severity) => {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'sev-critical';
    case 'HIGH': return 'sev-high';
    case 'MEDIUM': return 'sev-medium';
    case 'LOW': return 'sev-low';
    default: return 'sev-unknown';
  }
};

function App() {
  const [activeTab, setActiveTab] = useState('scan');
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');
  const [selectedTechVulns, setSelectedTechVulns] = useState(null);
  const [deepCrawling, setDeepCrawling] = useState(false);
  const [deepCrawlDone, setDeepCrawlDone] = useState(false);
  const [deepCrawlError, setDeepCrawlError] = useState('');
  const [crawlContext, setCrawlContext] = useState(null);
  const [jobProgress, setJobProgress] = useState(0);
  const [jobMessage, setJobMessage] = useState('');
  const [currentJobId, setCurrentJobId] = useState(null);

  const pollJobStatus = async (jobId, onComplete, onError, onProgress) => {
    try {
      const interval = setInterval(async () => {
        try {
          const res = await axios.get(`${API_BASE}/jobs/${jobId}`);
          const { state, progress, result, failedReason } = res.data;
          
          if (progress?.percentage) {
             onProgress(progress.percentage, progress.message || '');
          } else if (typeof progress === 'number') {
             onProgress(progress, '');
          }

          if (state === 'completed') {
            clearInterval(interval);
            onComplete(result);
          } else if (state === 'failed') {
            clearInterval(interval);
            onError(failedReason || 'Job failed on the server.');
          }
        } catch (err) {
          console.error("Polling error:", err);
          clearInterval(interval);
          onError('Error checking scan status. The server might be unreachable.');
        }
      }, 2000);
    } catch (err) {
      onError('Failed to initiate polling.');
    }
  };

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url) return;

    setLoading(true);
    setError('');
    setResults(null);
    setDeepCrawlDone(false);
    setDeepCrawlError('');
    setCrawlContext(null);
    setJobProgress(0);
    setJobMessage('Submitting scan job...');

    let targetUrl = url.trim();
    if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;

    try {
      const response = await axios.post(`${API_BASE}/scan`, { url: targetUrl });
      const { jobId } = response.data;
      setCurrentJobId(jobId);
      
      await pollJobStatus(jobId, 
        (finalResult) => {
           setResults(finalResult);
           setLoading(false);
           setJobProgress(100);
        },
        (errMessage) => {
           setError(errMessage);
           setLoading(false);
        },
        (progPct, progMsg) => {
           setJobProgress(progPct);
           if (progMsg) setJobMessage(progMsg);
        }
      );
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to scan the target.');
      setLoading(false);
    }
  };

  const handleDeepCrawl = async () => {
    if (!results) return;
    setDeepCrawling(true);
    setDeepCrawlError('');
    try {
      const response = await axios.post(`${API_BASE}/deep-crawl`, { url: results.url });
      const { jobId } = response.data;

      await pollJobStatus(jobId,
        (finalResult) => {
           setCrawlContext(finalResult);
           setDeepCrawlDone(true);
           setDeepCrawling(false);
        },
        (errMessage) => {
           setDeepCrawlError(errMessage);
           setDeepCrawling(false);
        },
        () => {} // optional progress updates for deep crawl
      );
    } catch (err) {
      setDeepCrawlError(err.response?.data?.error || 'Deep crawl failed.');
      setDeepCrawling(false);
    }
  };

  const getGroupedDetections = () => {
    if (!results || !results.technologies) return {};
    const groups = {};
    results.technologies.forEach(tech => {
      const cats = tech.categories || ['Miscellaneous'];
      cats.forEach(cat => {
        const catName = typeof cat === 'string' ? cat : cat.name;
        if (!groups[catName]) groups[catName] = [];
        if (!groups[catName].some(t => t.name === tech.name)) {
          groups[catName].push({
            name: tech.name,
            version: tech.version,
            icon: tech.icon
          });
        }
      });
    });
    return groups;
  };

  const grouped = getGroupedDetections();

  const getRiskColor = (risk) => {
    switch (risk) {
      case 'HIGH': return 'var(--danger)';
      case 'MEDIUM': return 'var(--warning)';
      case 'LOW': return 'var(--success)';
      default: return 'var(--text-secondary)';
    }
  };

  return (
    <div className="app-container">
      <header>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '15px', marginBottom: '10px' }}>
          <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--primary)', filter: 'drop-shadow(0px 0px 8px rgba(59, 130, 246, 0.4))' }}>
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="M12 8v4" />
            <path d="M12 16h.01" />
            <circle cx="12" cy="12" r="8" strokeDasharray="2 4" strokeWidth="0.5" />
            <path d="M8 12h8" strokeWidth="0.5" />
            <path d="M12 8l-4 4 4 4" strokeWidth="0.5" />
          </svg>
          <div className="logo" style={{ margin: 0, fontSize: '2.5rem', letterSpacing: '2px' }}>Vulnexa</div>
        </div>
        <h1>Security Exposure Analyzer</h1>
        <p className="subtitle">
          Professional-grade security scanning for technologies, cookies, and suspicious scripts.
        </p>
      </header>

      <main>
        <div className="nav-tabs">
          <button 
            className={`nav-tab ${activeTab === 'scan' ? 'active' : ''}`}
            onClick={() => setActiveTab('scan')}
          >
            🔍 Security Scanner
          </button>

        </div>

        {activeTab === 'scan' && (
          <>
            <div className="search-container">
          <form className="search-form glass-panel" onSubmit={handleScan}>
            <input
              type="text"
              className="search-input"
              placeholder="Enter target URL..."
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={loading}
              autoFocus
            />
            <button type="submit" className="btn-primary" disabled={loading || !url}>
              {loading ? 'Analyzing Layers...' : (
                <>
                  <SearchIcon />
                  Deep Scan
                </>
              )}
            </button>
          </form>
        </div>

        {/* Live Attack Console */}
        <AttackConsole isActive={loading} />

        {error && <div className="error-message glass-panel" style={{ color: 'var(--danger)', marginTop: '1rem' }}>{error}</div>}

        {loading && (
          <div className="loader-container">
            <div className="spinner"></div>
            <div className="loader-text">{jobMessage || 'Probing Network & Runtime JS...'}</div>
            {jobProgress > 0 && <div style={{marginTop: '1rem', color: 'var(--primary)'}}>{jobProgress}%</div>}
          </div>
        )}

        {results && !loading && (
          <div className="results-wrapper fadeIn">
            {/* Scan Summary Alert */}
            {results.summary && (
              <div className="glass-panel scan-summary-alert fadeIn">
                <div className="summary-icon">
                  {results.summary.totalHighRisks > 0 ? '⚠️' : '🛡️'}
                </div>
                <div className="summary-content">
                  <div className="summary-title">Website Security Summary</div>
                  <div className="summary-text">{results.summary.message}</div>
                  <div className="summary-hint">{results.summary.recommendation}</div>
                </div>
                <div className="summary-stats">
                  <div className="stat-item">
                    <div className="stat-val">{results.summary.totalCookies}</div>
                    <div className="stat-label">Cookies</div>
                  </div>
                  <div className="stat-item">
                    <div className={`stat-val ${results.summary.totalHighRisks > 0 ? 'neg' : ''}`}>
                      {results.summary.totalHighRisks}
                    </div>
                    <div className="stat-label">High Risks</div>
                  </div>
                </div>
              </div>
            )}

            {/* Scan Metadata */}
            <div className="glass-panel results-header-info fadeIn">
              <div className="scan-meta">
                <div className="meta-item">
                  <span className="meta-label">Target:</span>
                  <span className="meta-value">{results.target || results.url}</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Status:</span>
                  <span className="status-badge success">Complete</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Duration:</span>
                  <span className="meta-value">{results.scanDuration || 'N/A'}</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Scan Date:</span>
                  <span className="meta-value">
                    {new Date(results.timestamp).toLocaleString()}
                  </span>
                </div>
                <div className="meta-item" style={{ marginLeft: 'auto' }}>
                  {!deepCrawlDone ? (
                    <button
                      className="btn-deep-crawl"
                      onClick={handleDeepCrawl}
                      disabled={deepCrawling}
                      title="Run full Puppeteer-based crawl for deeper endpoint discovery"
                    >
                      {deepCrawling ? (
                        <><span className="btn-spinner" />Crawling...</>
                      ) : (
                        <>🕷️ Deep Crawl</>
                      )}
                    </button>
                  ) : (
                    <span className="status-badge success">✅ Deep Crawl Done</span>
                  )}
                  {deepCrawlError && <span style={{ color: 'var(--danger)', fontSize: '0.75rem', marginLeft: '0.5rem' }}>{deepCrawlError}</span>}
                </div>
                
                {/* Download Report Buttons */}
                <div className="meta-item download-actions">
                  <div className="btn-group">
                    <button 
                      className="btn-secondary" 
                      onClick={() => window.open(`${API_BASE}/reports/pdf/${currentJobId}`, '_blank')}
                      title="Download full professional PDF report"
                    >
                      📄 Download PDF
                    </button>
                    <button 
                      className="btn-secondary" 
                      onClick={() => window.open(`${API_BASE}/reports/html/${currentJobId}`, '_blank')}
                      title="Open interactive HTML report"
                    >
                      🌐 HTML
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div className="results-grid">
              
              {/* 1. Technologies First */}
              {Object.entries(grouped).map(([category, techs]) => (
                <div key={category} className="result-card glass-panel tech-card">
                  <div className="result-header">
                    <CategoryIcon category={category} />
                    <h3 className="result-title">{category}</h3>
                  </div>
                  <div className="tags-container">
                    {techs.map((t, i) => (
                      <span 
                        key={i} 
                        className={`tag tech-tag ${t.version ? 'clickable-tag' : ''}`}
                        onClick={() => t.version && setSelectedTechVulns({ 
                          name: t.name, 
                          vulns: results.vulnerabilities?.[t.name] || [] 
                        })}
                        title={t.version ? "Click to view vulnerability details" : ""}
                      >
                        {t.icon && (
                          <img
                            src={`https://www.wappalyzer.com/images/icons/${encodeURIComponent(t.icon)}`}
                            alt=""
                            className="tech-icon"
                            onError={(e) => e.target.style.display = 'none'}
                          />
                        )}
                        <span className="tech-name">{t.name}</span>
                        {t.version && (
                          <span className="tech-version">{t.version}</span>
                        )}
                        {results.vulnerabilities?.[t.name] && results.vulnerabilities[t.name].length > 0 && (
                          <span className="vuln-badge" style={{ pointerEvents: 'none' }}>
                            ⚠️ {results.vulnerabilities[t.name].length}
                            <span style={{marginLeft: '4px', fontSize: '0.6rem', opacity: 0.9}}>
                              ({results.vulnerabilities[t.name].sort((a,b) => (b.score || 0) - (a.score || 0))[0]?.severity})
                            </span>
                          </span>
                        )}
                      </span>
                    ))}
                  </div>
                </div>
              ))}

              {/* 2. Security Headers */}
              <div className="result-card glass-panel security-card">
                <div className="result-header">
                  <span className="category-icon">🛡️</span>
                  <h3 className="result-title">Security Headers</h3>
                </div>
                <div className="security-list">
                  {results.securityHeaders && Object.entries(results.securityHeaders).map(([k, v]) => (
                    <div key={k} className="security-item">
                      <span className="sec-key">{k}:</span>
                      <span className={`sec-val ${v === 'Not Enabled' ? 'neg' : 'pos'}`}>{v}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* 3. SSL/TLS Security */}
              {results.sslInfo && (
                <div className="result-card glass-panel ssl-card">
                  <div className="result-header">
                    <span className="category-icon">🔒</span>
                    <h3 className="result-title">SSL/TLS Security</h3>
                  </div>
                  <div className="ssl-details">
                    <div className="ssl-main-status">
                      <span className={`status-pill ${results.sslInfo.valid ? 'success' : 'danger'}`}>
                        {results.sslInfo.valid ? 'Certificate Valid' : 'Insecure / Expired'}
                      </span>
                    </div>
                    <div className="ssl-info-grid">
                      <div className="ssl-item">
                        <span className="ssl-label">TLS Version:</span>
                        <span className={`ssl-val ${results.sslInfo.isProtocolSecure ? 'pos' : 'neg'}`}>{results.sslInfo.protocol}</span>
                      </div>
                      <div className="ssl-item">
                        <span className="ssl-label">Expiry:</span>
                        <span className={`ssl-val ${results.sslInfo.remainingDays < 30 ? 'neg' : ''}`}>
                          {results.sslInfo.validTo ? new Date(results.sslInfo.validTo).toLocaleDateString() : 'Unknown'} ({results.sslInfo.remainingDays || 0} days left)
                        </span>
                      </div>
                      <div className="ssl-item">
                        <span className="ssl-label">Cipher:</span>
                        <span className="ssl-val small-font">{results.sslInfo.cipher || 'Not Available'}</span>
                      </div>
                      <div className="ssl-item">
                        <span className="ssl-label">Issuer:</span>
                        <span className="ssl-val">{results.sslInfo.issuer || 'Not Available'}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* 4. Defense Infrastructure */}
              <div className="result-card glass-panel defense-card">
                <div className="result-header">
                  <span className="category-icon">🛡️</span>
                  <h3 className="result-title">Defense Infrastructure</h3>
                </div>
                <div className="defense-list">
                   {results.waf ? (
                     <div className="defense-item">
                       <span className="def-key">WAF Detected:</span>
                       <span className="def-val pos">{results.waf.name || 'Unknown WAF'}</span>
                       {results.waf.confidence && <div style={{fontSize: '0.75rem', color: 'var(--text-muted)'}}>Confidence: {results.waf.confidence}%</div>}
                     </div>
                   ) : (
                     <div className="defense-item">
                       <span className="def-key">WAF Detected:</span>
                       <span className="def-val neg">No WAF Identified</span>
                     </div>
                   )}
                   {results.domainIntel && results.domainIntel.asn && (
                     <div className="defense-item" style={{ marginTop: '1rem' }}>
                       <span className="def-key">Hosting/Cloud:</span>
                       <span className="def-val">{results.domainIntel.asn.organization}</span>
                     </div>
                   )}
                </div>
              </div>

              {/* 5. Domain Intelligence & OSINT */}
              <div style={{ gridColumn: '1 / -1' }}>
                <DomainIntelligence domainIntel={results.domainIntel} />
              </div>

              {/* 6. Hacker OSINT & Recon Intelligence (ReconDashboard) */}
              <div style={{ gridColumn: '1 / -1' }}>
                <ReconDashboard domainIntel={results.domainIntel} behaviorProfiling={results.behaviorProfiling} />
              </div>

              {/* Attack Chains */}
              <div style={{ gridColumn: '1 / -1' }}>
                <AttackChainView chains={results.attackChains} />
              </div>

              {/* Suspicious Scripts */}
              <div style={{ gridColumn: '1 / -1' }}>
                <SuspiciousScripts scripts={results.suspiciousScripts} />
              </div>

              {/* Port Scans */}
              <PortScanResults targetUrl={results.target || results.url} />

              {/* Cookies */}
              <CookieSecurity cookieSecurity={results.cookieSecurity} />

              {/* Discovery & Exposure */}
              <DiscoveryResults 
                adminPanels={results.adminPanels}
                hiddenEndpoints={results.hiddenEndpoints}
                secretLeaks={results.secretLeaks}
                directories={results.directories}
                corsIssues={results.corsIssues}
                graphqlFindings={results.graphqlFindings}
                openRedirects={results.openRedirects}
                ssrfFindings={results.ssrfFindings}
                authBypasses={results.authBypasses}
                rateLimits={results.rateLimits}
                sqli={results.sqli}
                cmdInjection={results.cmdInjection}
                idors={results.idors}
                jwtIssues={results.jwtIssues}
                scanContext={crawlContext || results.scanContext}
                waf={results.waf}
              />
            </div>
          </div>
        )}
          </>
        )}


      </main>

      {/* Vulnerability Modal */}
      {selectedTechVulns && (
        <div className="modal-overlay fadeIn" onClick={() => setSelectedTechVulns(null)}>
          <div className="modal-content glass-panel" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div style={{ flex: 1 }}>
                <h2 className="modal-title">Vulnerabilities: {selectedTechVulns.name}</h2>
                <div style={{ display: 'flex', gap: '0.8rem', marginTop: '0.4rem', alignItems: 'center' }}>
                  <span className="status-badge" style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)', fontSize: '0.75rem' }}>
                    {selectedTechVulns.vulns.length} Issues Found
                  </span>
                  {selectedTechVulns.vulns.length > 0 && (
                    <span 
                      className={`risk-pill small ${getSeverityClass(
                        selectedTechVulns.vulns.sort((a,b) => (b.score || 0) - (a.score || 0))[0]?.severity
                      )}`}
                    >
                      Overall Risk: {selectedTechVulns.vulns.sort((a,b) => (b.score || 0) - (a.score || 0))[0]?.severity}
                    </span>
                  )}
                </div>
              </div>
              <button className="close-btn" onClick={() => setSelectedTechVulns(null)}>&times;</button>
            </div>
            <div className="modal-body">
              {selectedTechVulns.vulns.length > 0 ? (
                selectedTechVulns.vulns.map((v, i) => (
                  <div key={i} className="vuln-item">
                    <div className="vuln-meta">
                      <span className="vuln-id">{v.id}</span>
                      <span className={`vuln-severity ${getSeverityClass(v.severity)}`}>
                        {v.severity} ({v.score})
                      </span>
                    </div>
                    <p className="vuln-desc">{v.description}</p>
                    <div className="vuln-footer">
                      <span className="vuln-date">Published: {new Date(v.published).toLocaleDateString()}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                  <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🛡️</div>
                  <h3 style={{ color: 'var(--success)', marginBottom: '0.5rem' }}>No Vulnerabilities Found</h3>
                  <p>This version of <strong>{selectedTechVulns.name}</strong> appears to be secure or is too new for listed CVEs.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
