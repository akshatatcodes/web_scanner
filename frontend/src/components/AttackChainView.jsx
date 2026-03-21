import React, { useState } from 'react';

const AttackChainView = ({ chains }) => {
  const [expandedChain, setExpandedChain] = useState(null);

  if (!chains || chains.length === 0) return null;

  return (
    <div className="attack-chain-container fadeIn">
      <div className="section-header">
        <span className="section-icon">🧨</span>
        <h2 className="section-title">Chained Exploit Paths (Attack Graph)</h2>
      </div>

      <div className="chains-list">
        {chains.map((chain, index) => (
          <div key={index} className={`attack-chain-card glass-panel sev-${chain.severity.toLowerCase()}`}>
            <div className="chain-header" onClick={() => setExpandedChain(expandedChain === index ? null : index)}>
              <div className="chain-main-info">
                <span className="chain-severity-badge">{chain.severity}</span>
                <h3 className="chain-name">{chain.name}</h3>
              </div>
              <div className="chain-meta-info">
                <span className="chain-confidence">Confidence: {(chain.confidence * 100).toFixed(0)}%</span>
                <span className={`expand-icon ${expandedChain === index ? 'rotated' : ''}`}>▼</span>
              </div>
            </div>

            <div className="chain-visual-path">
              {chain.path.map((step, i) => (
                <React.Fragment key={i}>
                  <div className="path-step">
                    <span className="step-text">{step}</span>
                  </div>
                  {i < chain.path.length - 1 && <div className="path-arrow">→</div>}
                </React.Fragment>
              ))}
            </div>

            {expandedChain === index && (
              <div className="chain-details slideDown">
                <p className="chain-description">{chain.description}</p>
                
                <div className="evidence-section">
                  <h4>Linked Evidence</h4>
                  <div className="evidence-grid">
                    {Object.entries(chain.evidence).map(([key, value]) => (
                      <div key={key} className="evidence-item">
                        <span className="evidence-key">{key.replace(/_/g, ' ')}:</span>
                        <code className="evidence-value">{value}</code>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      <style jsx>{`
        .attack-chain-container {
          margin-bottom: 2rem;
          width: 100%;
        }
        .chains-list {
          display: flex;
          flex-direction: column;
          gap: 1.5rem;
        }
        .attack-chain-card {
          border-left: 4px solid var(--text-muted);
          padding: 1.5rem;
          transition: transform 0.2s ease;
        }
        .attack-chain-card.sev-critical { border-left-color: #ff4d4d; background: rgba(255, 77, 77, 0.05); }
        .attack-chain-card.sev-high { border-left-color: #ff944d; background: rgba(255, 148, 77, 0.05); }
        
        .chain-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          cursor: pointer;
          margin-bottom: 1.5rem;
        }
        .chain-main-info {
          display: flex;
          align-items: center;
          gap: 1rem;
        }
        .chain-severity-badge {
          font-size: 0.7rem;
          font-weight: 800;
          padding: 0.2rem 0.6rem;
          border-radius: 4px;
          background: rgba(255,255,255,0.1);
          letter-spacing: 1px;
        }
        .chain-name {
          margin: 0;
          font-size: 1.2rem;
          color: var(--text-primary);
        }
        .chain-meta-info {
          display: flex;
          align-items: center;
          gap: 1rem;
          color: var(--text-secondary);
          font-size: 0.8rem;
        }

        .chain-visual-path {
          display: flex;
          align-items: center;
          gap: 0.8rem;
          margin-bottom: 1rem;
          overflow-x: auto;
          padding-bottom: 0.5rem;
        }
        .path-step {
          background: rgba(255,255,255,0.05);
          padding: 0.5rem 1rem;
          border-radius: 20px;
          border: 1px solid rgba(255,255,255,0.1);
          white-space: nowrap;
        }
        .step-text {
          font-weight: 600;
          font-size: 0.9rem;
        }
        .path-arrow {
          color: var(--text-muted);
          font-weight: bold;
        }

        .chain-details {
          margin-top: 1.5rem;
          padding-top: 1.5rem;
          border-top: 1px solid rgba(255,255,255,0.1);
        }
        .chain-description {
          color: var(--text-secondary);
          line-height: 1.6;
          margin-bottom: 1.5rem;
        }
        .evidence-section h4 {
          font-size: 0.9rem;
          margin-bottom: 1rem;
          color: var(--text-primary);
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        .evidence-grid {
          display: grid;
          grid-template-columns: 1fr;
          gap: 0.8rem;
        }
        .evidence-item {
          background: rgba(0,0,0,0.2);
          padding: 0.8rem;
          border-radius: 8px;
          display: flex;
          flex-direction: column;
          gap: 0.4rem;
        }
        .evidence-key {
          font-size: 0.7rem;
          color: var(--text-muted);
          text-transform: uppercase;
        }
        .evidence-value {
          font-size: 0.85rem;
          color: var(--warning);
          word-break: break-all;
        }
        
        .expand-icon {
          transition: transform 0.3s ease;
        }
        .expand-icon.rotated {
          transform: rotate(180deg);
        }
      `}</style>
    </div>
  );
};

export default AttackChainView;
