import { useState } from 'react';
import axios from 'axios';
import './index.css';

// SVG Icons
const SearchIcon = () => (
  <svg xmlns="http://www.0000.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="8"></circle>
    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
  </svg>
);

const CheckCircleIcon = () => (
  <svg xmlns="http://www.worg/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--success)' }}>
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
    <polyline points="22 4 12 14.01 9 11.01"></polyline>
  </svg>
);

const ShieldIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
  </svg>
);

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url) return;

    setLoading(true);
    setError('');
    setResults(null);

    try {
      const response = await axios.post('http://localhost:5000/api/scan', { url });
      setResults(response.data);
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to scan the target URL. Make sure the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const renderTags = (items, fallbackText = "Not Detected") => {
    if (!items || items.length === 0) {
      return <span className="tag-empty">{fallbackText}</span>;
    }
    return (
      <div className="tags-container">
        {items.map((item, index) => (
          <span key={index} className="tag">{item}</span>
        ))}
      </div>
    );
  };

  return (
    <div className="app-container">
      <header>
        <h1>Exposure Analyzer</h1>
        <p className="subtitle">
          Detect technology stacks, frameworks, and uncover potential exposure footprint of any valid web target.
        </p>
      </header>

      <main>
        <div className="search-container">
          <form className="search-form glass-panel" style={{ padding: '0.5rem' }} onSubmit={handleScan}>
            <input
              type="text"
              className="search-input"
              placeholder="Enter target URL (e.g. https://example.com)..."
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={loading}
              autoFocus
            />
            <button type="submit" className="btn-primary" disabled={loading || !url}>
              {loading ? 'Scanning...' : (
                <>
                  <SearchIcon />
                  Analyze
                </>
              )}
            </button>
          </form>
        </div>

        {error && (
          <div className="error-message glass-panel">
            <strong>Error: </strong> {error}
          </div>
        )}

        {loading && (
          <div className="loader-container">
            <div className="spinner"></div>
            <div className="loader-text">Analyzing Target Infrastructure...</div>
          </div>
        )}

        {results && !loading && (
          <div className="results-grid">
            <div className="result-card glass-panel">
              <div className="result-header">
                <div className="result-icon">🌐</div>
                <h3 className="result-title">Frontend Engine</h3>
              </div>
              {renderTags(results.detections?.frontend, "No JavaScript framework detected")}
            </div>

            <div className="result-card glass-panel">
              <div className="result-header">
                <div className="result-icon">⚙️</div>
                <h3 className="result-title">Backend Technology</h3>
              </div>
              {renderTags(results.detections?.backend, "No specific backend detected")}
            </div>

            <div className="result-card glass-panel">
              <div className="result-header">
                <div className="result-icon">📝</div>
                <h3 className="result-title">Content Management</h3>
              </div>
              {renderTags(results.detections?.cms, "No known CMS detected")}
            </div>

            <div className="result-card glass-panel">
              <div className="result-header">
                <div className="result-icon">🖥️</div>
                <h3 className="result-title">Web Server</h3>
              </div>
              {renderTags(results.detections?.server, "Server headers hidden or unknown")}
            </div>

            <div className="result-card glass-panel" style={{ gridColumn: '1 / -1', background: 'rgba(16, 185, 129, 0.05)', borderColor: 'rgba(16, 185, 129, 0.2)' }}>
              <div className="result-header" style={{ borderBottomColor: 'rgba(16, 185, 129, 0.2)' }}>
                <CheckCircleIcon />
                <h3 className="result-title" style={{ color: 'var(--success)' }}>Scan Complete</h3>
              </div>
              <p style={{ color: 'var(--text-secondary)' }}>
                Analyzed URL: <strong style={{ color: 'var(--text-primary)' }}>{results.url}</strong> <br />
                Status Code: <strong style={{ color: 'var(--text-primary)' }}>{results.status}</strong>
              </p>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
