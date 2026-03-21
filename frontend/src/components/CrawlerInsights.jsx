import React, { useState } from 'react';

const CrawlerInsights = ({ scanContext }) => {
  const [filter, setFilter] = useState('ALL');
  const [search, setSearch] = useState('');

  if (!scanContext || !scanContext.endpoints) return null;

  const { endpoints, stats, metadata } = scanContext;

  const filteredEndpoints = endpoints.filter(e => {
    const matchesFilter = filter === 'ALL' || e.type.toUpperCase() === filter || e.source.toUpperCase() === filter;
    const matchesSearch = e.url.toLowerCase().includes(search.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const getSourceIcon = (source) => {
    switch (source.toLowerCase()) {
      case 'link': return '🌐';
      case 'xhr':
      case 'fetch': return '⚡';
      case 'form': return '📝';
      case 'spa':
      case 'script': return '🧠';
      default: return '🔗';
    }
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'high': return '#ff4d4d';
      case 'medium': return '#ff944d';
      case 'low': return 'var(--text-muted)';
      default: return 'var(--text-muted)';
    }
  };

  return (
    <div className="crawler-insights glass-panel fadeIn">
      <div className="section-header">
        <span className="section-icon">🕵️‍♂️</span>
        <h2 className="section-title">Deep Discovery Insights (ELITE Crawler)</h2>
        <div className="discovery-stats">
          <div className="disc-stat">
            <span className="disc-val">{stats?.uniqueEndpoints || 0}</span>
            <span className="disc-label">Unique Assets</span>
          </div>
          <div className="disc-stat">
            <span className="disc-val">{metadata?.pagesVisited || 0}</span>
            <span className="disc-label">Pages Crawled</span>
          </div>
        </div>
      </div>

      <div className="filter-bar">
        <div className="filter-buttons">
          {['ALL', 'API', 'AUTH', 'ADMIN', 'FORM'].map(f => (
            <button 
              key={f}
              className={`filter-btn ${filter === f ? 'active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f}
            </button>
          ))}
        </div>
        <div className="search-box">
          <input 
            type="text" 
            placeholder="Search endpoints..." 
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      <div className="endpoints-table-container">
        <table className="endpoints-table">
          <thead>
            <tr>
              <th>Method</th>
              <th>Source</th>
              <th>Endpoint / Asset</th>
              <th>Type</th>
              <th>Params</th>
            </tr>
          </thead>
          <tbody>
            {filteredEndpoints.map((e, i) => (
              <tr key={i} className={`endpoint-row priority-${e.priority}`}>
                <td>
                  <span className={`method-badge ${e.method.toLowerCase()}`}>
                    {e.method}
                  </span>
                </td>
                <td className="source-cell">
                  {getSourceIcon(e.source)} <span className="source-label">{e.source}</span>
                </td>
                <td className="url-cell" title={e.url}>
                  <div className="url-wrapper">
                    <code style={{ color: getPriorityColor(e.priority) }}>
                      {e.url.length > 60 ? e.url.substring(0, 60) + '...' : e.url}
                    </code>
                    <button 
                      className="copy-url-btn" 
                      onClick={() => navigator.clipboard.writeText(e.url)}
                      title="Copy full URL"
                    >
                      📋
                    </button>
                  </div>
                </td>
                <td>
                  <span className={`type-label type-${e.type}`}>
                    {e.type}
                  </span>
                </td>
                <td>
                  <span className="param-count">
                    {e.params?.length || 0}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <style jsx>{`
        .crawler-insights {
          margin-bottom: 2rem;
          padding: 1.5rem;
          width: 100%;
        }
        .discovery-stats {
          display: flex;
          gap: 1.5rem;
          margin-left: auto;
        }
        .disc-stat {
          display: flex;
          flex-direction: column;
          align-items: flex-end;
        }
        .disc-val {
            font-size: 1.2rem;
            font-weight: 800;
            color: var(--warning);
        }
        .disc-label {
            font-size: 0.65rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
        }

        .filter-bar {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 1.5rem;
          gap: 1rem;
          flex-wrap: wrap;
        }
        .filter-buttons {
          display: flex;
          gap: 0.5rem;
        }
        .filter-btn {
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.1);
          color: var(--text-secondary);
          padding: 0.4rem 0.8rem;
          border-radius: 4px;
          font-size: 0.75rem;
          cursor: pointer;
          transition: all 0.2s ease;
        }
        .filter-btn.active {
          background: var(--primary);
          color: white;
          border-color: var(--primary);
        }
        .search-box input {
          background: rgba(0,0,0,0.2);
          border: 1px solid rgba(255,255,255,0.1);
          color: white;
          padding: 0.4rem 1rem;
          border-radius: 4px;
          min-width: 250px;
        }

        .endpoints-table-container {
          max-height: 400px;
          overflow-y: auto;
          border: 1px solid rgba(255,255,255,0.05);
          border-radius: 8px;
        }
        .endpoints-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 0.85rem;
        }
        .endpoints-table th {
          text-align: left;
          padding: 1rem;
          background: rgba(255,255,255,0.02);
          color: var(--text-muted);
          text-transform: uppercase;
          font-size: 0.7rem;
          letter-spacing: 1px;
          position: sticky;
          top: 0;
          z-index: 10;
        }
        .endpoints-table td {
          padding: 0.8rem 1rem;
          border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .endpoint-row:hover {
          background: rgba(255,255,255,0.03);
        }

        .method-badge {
          padding: 0.2rem 0.5rem;
          border-radius: 4px;
          font-size: 0.7rem;
          font-weight: bold;
          text-transform: uppercase;
        }
        .method-badge.get { background: rgba(77, 255, 148, 0.1); color: #4dff94; border: 1px solid rgba(77, 255, 148, 0.2); }
        .method-badge.post { background: rgba(255, 148, 77, 0.1); color: #ff944d; border: 1px solid rgba(255, 148, 77, 0.2); }
        .method-badge.put { background: rgba(77, 148, 255, 0.1); color: #4d94ff; border: 1px solid rgba(77, 148, 255, 0.2); }

        .source-cell {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          white-space: nowrap;
        }
        .source-label {
          font-size: 0.7rem;
          color: var(--text-muted);
        }

        .url-cell code {
          background: transparent;
          font-family: 'JetBrains Mono', monospace;
        }
        
        .url-wrapper {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        
        .copy-url-btn {
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.1);
          color: var(--text-muted);
          border-radius: 4px;
          cursor: pointer;
          font-size: 0.8rem;
          padding: 0.2rem 0.4rem;
          opacity: 0.7;
          transition: all 0.2s ease;
        }
        
        .copy-url-btn:hover {
          opacity: 1;
          background: rgba(255,255,255,0.1);
          color: white;
        }

        .type-label {
          font-size: 0.7rem;
          padding: 0.2rem 0.4rem;
          border-radius: 4px;
          text-transform: capitalize;
        }
        .type-admin { color: #ff4d4d; background: rgba(255, 77, 77, 0.1); }
        .type-auth { color: #ff944d; background: rgba(255, 148, 77, 0.1); }
        .type-api { color: #4d94ff; background: rgba(77, 148, 255, 0.1); }
        .type-static { color: var(--text-muted); }

        .param-count {
          color: var(--warning);
          font-weight: bold;
        }
      `}</style>
    </div>
  );
};

export default CrawlerInsights;
