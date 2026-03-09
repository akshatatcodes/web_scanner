import { useState } from 'react';
import axios from 'axios';
import './index.css';

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
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');
  const [selectedTechVulns, setSelectedTechVulns] = useState(null);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url) return;

    setLoading(true);
    setError('');
    setResults(null);

    let targetUrl = url.trim();
    if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;

    try {
      const response = await axios.post('http://localhost:5000/api/scan', { url: targetUrl });
      setResults(response.data);
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to scan the target.');
    } finally {
      setLoading(false);
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
        // Prevent duplicates in same category
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

  return (
    <div className="app-container">
      <header>
        <div className="logo">SUPER ANALYZER PRO</div>
        <h1>Multi-Layer Web Profiler</h1>
        <p className="subtitle">
          Advanced fingerprinting using Wappalyzer Core, Network Analysis, and Runtime Probing.
        </p>
      </header>

      <main>
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

        {error && <div className="error-message glass-panel">{error}</div>}

        {loading && (
          <div className="loader-container">
            <div className="spinner"></div>
            <div className="loader-text">Probing Network & Runtime JS...</div>
          </div>
        )}

        {results && !loading && (
          <div className="results-wrapper fadeIn">
            <div className="results-header-info glass-panel">
              <div className="scan-meta">
                <div className="meta-item">
                  <span className="meta-label">Target:</span>
                  <span className="meta-value">{results.url}</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">Provider:</span>
                  <span className="status-badge success">{results.hostingProvider || 'Unknown'}</span>
                </div>
                <div className="meta-item">
                  <span className="meta-label">IP Address:</span>
                  <span className="meta-value">{results.dnsInfo?.ip?.[0] || 'Unknown'}</span>
                </div>
              </div>
            </div>

            <div className="results-grid">
              {/* Infrastructure & Security as priority cards */}
              <div className="result-card glass-panel security-card">
                <div className="result-header">
                  <CategoryIcon category="Security" />
                  <h3 className="result-title">Security Headers</h3>
                </div>
                <div className="security-list">
                  {Object.entries(results.securityHeaders).map(([k, v]) => (
                    <div key={k} className="security-item">
                      <span className="sec-key">{k}:</span>
                      <span className={`sec-val ${v === 'Not Enabled' ? 'neg' : 'pos'}`}>{v}</span>
                    </div>
                  ))}
                </div>
              </div>

              {Object.entries(grouped).map(([category, techs]) => (
                <div key={category} className="result-card glass-panel">
                  <div className="result-header">
                    <CategoryIcon category={category} />
                    <h3 className="result-title">{category}</h3>
                  </div>
                  <div className="tags-container">
                    {techs.map((t, i) => (
                      <span key={i} className="tag tech-tag">
                        {t.icon && (
                          <img
                            src={`https://www.wappalyzer.com/images/icons/${encodeURIComponent(t.icon)}`}
                            alt=""
                            className="tech-icon"
                            onError={(e) => e.target.style.display = 'none'}
                          />
                        )}
                        <span className="tech-name">{t.name}</span>
                        {t.version && <span className="tech-version">{t.version}</span>}
                        {results.vulnerabilities?.[t.name] && (
                          <span
                            className="vuln-badge clickable"
                            title="Click to view vulnerabilities"
                            onClick={() => setSelectedTechVulns({ name: t.name, vulns: results.vulnerabilities[t.name] })}
                          >
                            ⚠️ {results.vulnerabilities[t.name].length}
                          </span>
                        )}
                      </span>
                    ))}
                  </div>
                </div>
              ))}

            </div>
          </div>
        )}
      </main>

      {/* Vulnerability Modal */}
      {selectedTechVulns && (
        <div className="modal-overlay fadeIn" onClick={() => setSelectedTechVulns(null)}>
          <div className="modal-content glass-panel" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">Vulnerabilities: {selectedTechVulns.name}</h2>
              <button className="close-btn" onClick={() => setSelectedTechVulns(null)}>&times;</button>
            </div>
            <div className="modal-body">
              {selectedTechVulns.vulns.map((v, i) => (
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
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
