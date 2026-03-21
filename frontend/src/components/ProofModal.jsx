import React, { useState } from 'react';

const severityColor = {
    CRITICAL: 'var(--danger)',
    HIGH: '#f97316',
    MEDIUM: 'var(--warning)',
    LOW: 'var(--success)',
    INFO: 'var(--text-secondary)',
};

const ProofModal = ({ proof, onClose }) => {
    const [tab, setTab] = useState('overview');
    if (!proof) return null;

    const sev = proof.vulnerability?.includes('COMMAND') || proof.vulnerability?.includes('SQL') ? 'CRITICAL' :
                proof.vulnerability?.includes('AUTH') ? 'HIGH' :
                proof.vulnerability?.includes('REDIRECT') || proof.vulnerability?.includes('IDOR') ? 'HIGH' : 'MEDIUM';

    return (
        <div className="modal-overlay fadeIn" onClick={onClose}>
            <div
                className="modal-content glass-panel"
                onClick={e => e.stopPropagation()}
                style={{ maxWidth: '800px', width: '95%', maxHeight: '90vh', overflowY: 'auto' }}
            >
                {/* Header */}
                <div className="modal-header" style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '1rem', marginBottom: '1.2rem' }}>
                    <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                            <span style={{ fontSize: '1.3rem' }}>🧪</span>
                            <h2 className="modal-title" style={{ margin: 0 }}>Proof of Exploit</h2>
                            <span style={{
                                background: `${severityColor[sev]}22`,
                                color: severityColor[sev],
                                border: `1px solid ${severityColor[sev]}44`,
                                padding: '0.15rem 0.6rem',
                                borderRadius: '8px',
                                fontSize: '0.72rem',
                                fontWeight: 700,
                                letterSpacing: '0.05em'
                            }}>{sev}</span>
                        </div>
                        <div style={{ marginTop: '0.4rem', color: 'var(--text-muted)', fontSize: '0.8rem', fontFamily: 'monospace' }}>
                            {proof.vulnerability} — {proof.endpoint}
                        </div>
                    </div>
                    <button className="close-btn" onClick={onClose}>&times;</button>
                </div>

                {/* Tabs */}
                <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.2rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>
                    {['overview', 'request', 'response'].map(t => (
                        <button
                            key={t}
                            onClick={() => setTab(t)}
                            style={{
                                background: tab === t ? 'rgba(139,92,246,0.15)' : 'transparent',
                                color: tab === t ? 'var(--primary)' : 'var(--text-secondary)',
                                border: tab === t ? '1px solid rgba(139,92,246,0.3)' : '1px solid transparent',
                                borderRadius: '8px',
                                padding: '0.35rem 0.9rem',
                                fontSize: '0.82rem',
                                fontWeight: 600,
                                cursor: 'pointer',
                                textTransform: 'capitalize',
                                transition: 'all 0.2s'
                            }}
                        >{t}</button>
                    ))}
                </div>

                {/* Content */}
                {tab === 'overview' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                        <ProofRow label="Vulnerability" value={proof.vulnerability} mono />
                        <ProofRow label="Endpoint" value={proof.endpoint} mono />
                        <ProofRow label="Method" value={proof.method} mono />
                        <ProofRow label="Payload">
                            <pre style={preStyle}>{proof.payload || '—'}</pre>
                        </ProofRow>
                        {proof.meta?.evidence && (
                            <ProofRow label="Evidence">
                                <div style={{ color: '#facc15', fontSize: '0.85rem', fontFamily: 'monospace', padding: '0.6rem', background: 'rgba(250,204,21,0.06)', borderRadius: '8px', border: '1px solid rgba(250,204,21,0.15)' }}>
                                    {proof.meta.evidence}
                                </div>
                            </ProofRow>
                        )}
                        <div style={{ display: 'flex', gap: '1.5rem', marginTop: '0.5rem' }}>
                            {proof.response?.status > 0 && (
                                <div>
                                    <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginBottom: '0.2rem' }}>STATUS</div>
                                    <span style={{ fontFamily: 'monospace', fontWeight: 700, color: proof.response.status < 400 ? 'var(--success)' : 'var(--danger)' }}>
                                        {proof.response.status}
                                    </span>
                                </div>
                            )}
                            {proof.meta?.responseTime > 0 && (
                                <div>
                                    <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginBottom: '0.2rem' }}>RESPONSE TIME</div>
                                    <span style={{ fontFamily: 'monospace', fontWeight: 700, color: proof.meta.responseTime > 2000 ? 'var(--danger)' : 'var(--text-secondary)' }}>
                                        {proof.meta.responseTime}ms
                                    </span>
                                </div>
                            )}
                            {proof.meta?.timestamp && (
                                <div>
                                    <div style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginBottom: '0.2rem' }}>TIMESTAMP</div>
                                    <span style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                                        {new Date(proof.meta.timestamp).toLocaleTimeString()}
                                    </span>
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {tab === 'request' && (
                    <div>
                        <ProofRow label="URL" value={proof.request?.url} mono />
                        <ProofRow label="Method" value={proof.request?.method} mono />
                        {proof.payload && (
                            <ProofRow label="Payload">
                                <pre style={preStyle}>{proof.payload}</pre>
                            </ProofRow>
                        )}
                        <ProofRow label="Headers">
                            <pre style={preStyle}>{JSON.stringify(proof.request?.headers || {}, null, 2)}</pre>
                        </ProofRow>
                        {proof.request?.body && (
                            <ProofRow label="Body">
                                <pre style={preStyle}>{JSON.stringify(proof.request.body, null, 2)}</pre>
                            </ProofRow>
                        )}
                    </div>
                )}

                {tab === 'response' && (
                    <div>
                        <div style={{ marginBottom: '1rem', display: 'flex', gap: '1.5rem' }}>
                            <ProofRow label="Status" value={String(proof.response?.status || 0)} mono inline />
                        </div>
                        <ProofRow label="Headers">
                            <pre style={preStyle}>{JSON.stringify(proof.response?.headers || {}, null, 2)}</pre>
                        </ProofRow>
                        <ProofRow label="Body">
                            <pre style={{ ...preStyle, maxHeight: '280px', overflowY: 'auto' }}>
                                {proof.response?.body || '(empty)'}
                            </pre>
                        </ProofRow>
                    </div>
                )}

                <div style={{ marginTop: '1.5rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>ID: {proof.id}</span>
                    <button
                        className="btn-primary"
                        style={{ fontSize: '0.8rem', padding: '0.4rem 1rem' }}
                        onClick={() => {
                            navigator.clipboard?.writeText(JSON.stringify(proof, null, 2));
                        }}
                    >
                        📋 Copy JSON
                    </button>
                </div>
            </div>
        </div>
    );
};

const ProofRow = ({ label, value, children, mono, inline }) => (
    <div style={{ marginBottom: inline ? 0 : '0.9rem' }}>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem', fontWeight: 700, letterSpacing: '0.08em', marginBottom: '0.3rem', textTransform: 'uppercase' }}>
            {label}
        </div>
        {children || (
            <span style={{ fontFamily: mono ? 'monospace' : 'inherit', fontSize: '0.85rem', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                {value || '—'}
            </span>
        )}
    </div>
);

const preStyle = {
    background: 'rgba(0,0,0,0.25)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
    padding: '0.75rem 1rem',
    fontSize: '0.78rem',
    color: '#a5f3a5',
    fontFamily: 'monospace',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    margin: 0,
    overflowX: 'auto',
};

export default ProofModal;
