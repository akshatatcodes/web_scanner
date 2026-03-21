import React from 'react';

const ReconDashboard = ({ domainIntel }) => {
  if (!domainIntel || !domainIntel.reconScoring) return null;

  const { reconScoring, subdomainIntel, takeovers, wayback, asn, cdnBypass, jsRecon, githubRecon } = domainIntel;

  // Determine priority color
  const getPriorityColor = (priority) => {
    if (priority.includes("ATTACK FIRST")) return "var(--danger)";
    if (priority.includes("HIGH VALUE")) return "var(--warning)";
    return "var(--success)";
  };

  return (
    <div className="result-card glass-panel" style={{ gridColumn: '1 / -1', borderLeft: `4px solid ${getPriorityColor(reconScoring.priority)}` }}>
      <div className="result-header" style={{ borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '1rem', marginBottom: '1rem' }}>
        <h3 className="result-title" style={{ fontSize: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span className="category-icon">🎯</span> Hacker OSINT & Recon Intelligence
        </h3>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem' }}>
        
        {/* Risk Score & Priority */}
        <div style={{ backgroundColor: 'rgba(0,0,0,0.2)', padding: '1.5rem', borderRadius: '8px' }}>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '0.5rem' }}>Target Priority</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '1rem' }}>
            <span style={{ fontSize: '3rem', fontWeight: '800', color: getPriorityColor(reconScoring.priority) }}>
              {reconScoring.riskScore}
            </span>
            <span style={{ fontSize: '1.2rem', fontWeight: '600', color: getPriorityColor(reconScoring.priority) }}>
              {reconScoring.priority}
            </span>
          </div>
          <div style={{ marginTop: '1rem' }}>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Key Engagement Factors:</div>
            <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              {reconScoring.reasons.map((r, i) => <li key={i} style={{ marginBottom: '0.3rem' }}>{r}</li>)}
            </ul>
          </div>
        </div>

        {/* Infrastructure & CDN Bypass */}
        <div style={{ backgroundColor: 'rgba(0,0,0,0.2)', padding: '1.5rem', borderRadius: '8px' }}>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '1rem' }}>Infrastructure Pivot</div>
          {asn ? (
            <div style={{ marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.9rem', marginBottom: '0.3rem' }}><span style={{ color: 'var(--text-muted)' }}>Target IP:</span> {asn.ip}</div>
              <div style={{ fontSize: '0.9rem', marginBottom: '0.3rem' }}><span style={{ color: 'var(--text-muted)' }}>ASN Org:</span> {asn.organization}</div>
              <div style={{ fontSize: '0.9rem' }}><span style={{ color: 'var(--text-muted)' }}>Cloud/WAF:</span> {asn.isCloud ? <span style={{color: 'var(--warning)'}}>Yes</span> : <span style={{color: 'var(--danger)'}}>No (Direct)</span>}</div>
            </div>
          ) : (
             <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>No ASN data resolved.</div>
          )}

          {cdnBypass && cdnBypass.bypassed && (
             <div style={{ padding: '0.8rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid var(--danger)', borderRadius: '4px', marginTop: '0.5rem' }}>
               <div style={{ color: 'var(--danger)', fontWeight: 'bold', fontSize: '0.9rem', marginBottom: '0.2rem' }}>⚠️ CDN Bypassed</div>
               <div style={{ fontSize: '0.85rem' }}>Origin IP: <strong>{cdnBypass.originIp}</strong></div>
               <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Leaked via sub: {cdnBypass.leakedVia}</div>
             </div>
          )}
        </div>

        {/* Intelligence Mining (Wayback, JS, GH) */}
        <div style={{ backgroundColor: 'rgba(0,0,0,0.2)', padding: '1.5rem', borderRadius: '8px' }}>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '1rem' }}>Deep Mining Intelligence</div>
          
          <div style={{ marginBottom: '0.8rem' }}>
            <span style={{ fontSize: '1rem', marginRight: '0.5rem' }}>🕰️</span>
            <span style={{ fontSize: '0.9rem' }}>
              <strong>Wayback Machine:</strong> {wayback ? `${wayback.parameters?.length || 0} params, ${wayback.endpoints || 0} endpoints` : 'N/A'}
            </span>
          </div>

          <div style={{ marginBottom: '0.8rem' }}>
            <span style={{ fontSize: '1rem', marginRight: '0.5rem' }}>📜</span>
            <span style={{ fontSize: '0.9rem' }}>
              <strong>JS Hardcoded Secrets:</strong> {jsRecon ? `${jsRecon.stats?.totalSecrets || 0} found` : 'N/A'}
            </span>
          </div>

          <div style={{ marginBottom: '0.8rem' }}>
            <span style={{ fontSize: '1rem', marginRight: '0.5rem' }}>👾</span>
            <span style={{ fontSize: '0.9rem' }}>
              <strong>GitHub Source Leaks:</strong> {githubRecon ? `${githubRecon.totalCount || 0} matches` : 'N/A'}
            </span>
          </div>

          {takeovers && takeovers.length > 0 && (
             <div style={{ marginTop: '1rem', color: 'var(--danger)', fontSize: '0.9rem', fontWeight: 'bold' }}>
               🚨 {takeovers.length} Dangling CNAMEs Detected
             </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ReconDashboard;
