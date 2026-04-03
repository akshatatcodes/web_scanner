import React, { useState } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE || `http://${window.location.hostname}:5000/api`;

const severityColor = {
    CRITICAL: 'var(--danger)',
    HIGH: '#f97316',
    MEDIUM: 'var(--warning)',
    LOW: 'var(--success)',
    INFO: 'var(--text-secondary)',
};

const ProofModal = ({ proof, onClose }) => {
    const [activeTab, setActiveTab] = useState('overview');
    const [aiAnalysis, setAiAnalysis] = useState(null);
    const [isAiLoading, setIsAiLoading] = useState(false);
    const [aiError, setAiError] = useState(null);

    if (!proof) return null;

    const fetchAIAnalysis = async () => {
        if (aiAnalysis || isAiLoading) return;
        setIsAiLoading(true);
        setAiError(null);
        try {
            const resp = await fetch(`${API_BASE}/ai/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ finding: proof })
            });
            if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
            const data = await resp.json();
            setAiAnalysis(data);
        } catch (e) {
            console.error("AI Fetch error:", e);
            setAiError(e.message || 'Failed to reach backend.');
        } finally {
            setIsAiLoading(false);
        }
    };

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
                <div className="proof-tabs" style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.2rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>
                    <button
                        className={`proof-tab ${activeTab === 'overview' ? 'active' : ''}`}
                        onClick={() => setActiveTab('overview')}
                        style={{
                            background: activeTab === 'overview' ? 'rgba(139,92,246,0.15)' : 'transparent',
                            color: activeTab === 'overview' ? 'var(--primary)' : 'var(--text-secondary)',
                            border: activeTab === 'overview' ? '1px solid rgba(139,92,246,0.3)' : '1px solid transparent',
                            borderRadius: '8px',
                            padding: '0.35rem 0.9rem',
                            fontSize: '0.82rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            textTransform: 'capitalize',
                            transition: 'all 0.2s'
                        }}
                    >Overview</button>
                    <button
                        className={`proof-tab ${activeTab === 'request' ? 'active' : ''}`}
                        onClick={() => setActiveTab('request')}
                        style={{
                            background: activeTab === 'request' ? 'rgba(139,92,246,0.15)' : 'transparent',
                            color: activeTab === 'request' ? 'var(--primary)' : 'var(--text-secondary)',
                            border: activeTab === 'request' ? '1px solid rgba(139,92,246,0.3)' : '1px solid transparent',
                            borderRadius: '8px',
                            padding: '0.35rem 0.9rem',
                            fontSize: '0.82rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            textTransform: 'capitalize',
                            transition: 'all 0.2s'
                        }}
                    >Request</button>
                    <button
                        className={`proof-tab ${activeTab === 'response' ? 'active' : ''}`}
                        onClick={() => setActiveTab('response')}
                        style={{
                            background: activeTab === 'response' ? 'rgba(139,92,246,0.15)' : 'transparent',
                            color: activeTab === 'response' ? 'var(--primary)' : 'var(--text-secondary)',
                            border: activeTab === 'response' ? '1px solid rgba(139,92,246,0.3)' : '1px solid transparent',
                            borderRadius: '8px',
                            padding: '0.35rem 0.9rem',
                            fontSize: '0.82rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            textTransform: 'capitalize',
                            transition: 'all 0.2s'
                        }}
                    >Response</button>
                    <button
                        className={`proof-tab ${activeTab === 'ai' ? 'active' : ''}`}
                        style={{
                            borderLeft: '1px solid rgba(139,92,246,0.3)',
                            color: '#a78bfa',
                            background: activeTab === 'ai' ? 'rgba(139,92,246,0.15)' : 'transparent',
                            border: activeTab === 'ai' ? '1px solid rgba(139,92,246,0.3)' : '1px solid transparent',
                            borderRadius: '8px',
                            padding: '0.35rem 0.9rem',
                            fontSize: '0.82rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                            textTransform: 'capitalize',
                            transition: 'all 0.2s'
                        }}
                        onClick={() => {
                            setActiveTab('ai');
                            fetchAIAnalysis();
                        }}
                    >
                        ✨ AI Analysis
                    </button>
                </div>

                {/* Content */}
                {activeTab === 'overview' && (
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

                {activeTab === 'request' && (
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

                {activeTab === 'response' && (
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

                {activeTab === 'ai' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem', padding: '0.5rem 0' }}>
                        {isAiLoading ? (
                            <div style={{ padding: '3rem 1rem', textAlign: 'center' }}>
                                <div style={{ border: '3px solid rgba(139,92,246,0.1)', borderTop: '3px solid #a78bfa', borderRadius: '50%', width: '40px', height: '40px', margin: '0 auto 1.5rem', animation: 'spin 1s linear infinite' }} />
                                <div style={{ color: '#a78bfa', fontSize: '0.9rem', fontWeight: 600 }}>Analyzing exploit evidence with Cyber-AI...</div>
                            </div>
                        ) : aiAnalysis ? (
                            <>
                                <div style={{ 
                                    background: 'rgba(139,92,246,0.08)', 
                                    border: '1px solid rgba(139,92,246,0.2)', 
                                    borderRadius: '10px',
                                    padding: '1.2rem',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '1.2rem'
                                }}>
                                    <div style={{ fontSize: '1.8rem' }}>🧠</div>
                                    <div style={{ flex: 1 }}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: '0.4rem' }}>
                                            <span style={{ fontSize: '0.7rem', color: '#a78bfa', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.05em' }}>AI Confidence</span>
                                            <span style={{ fontWeight: 800, color: '#d946ef', fontSize: '0.9rem' }}>{(aiAnalysis.confidence * 100).toFixed(0)}%</span>
                                        </div>
                                        <div style={{ height: '6px', width: '100%', background: 'rgba(255,255,255,0.05)', borderRadius: '10px' }}>
                                            <div style={{ 
                                                height: '100%', 
                                                width: `${aiAnalysis.confidence * 100}%`, 
                                                background: 'linear-gradient(90deg, #8b5cf6, #d946ef)', 
                                                borderRadius: '10px',
                                                boxShadow: '0 0 10px rgba(139,92,246,0.4)'
                                            }} />
                                        </div>
                                    </div>
                                </div>

                                <div>
                                    <div style={{ color: '#a78bfa', fontSize: '0.7rem', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>Expert Analysis</div>
                                    <div style={{ fontSize: '0.86rem', color: '#e5e7eb', lineHeight: 1.6, background: 'rgba(255,255,255,0.02)', padding: '1rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }}>
                                        {aiAnalysis.explanation}
                                    </div>
                                </div>

                                <div>
                                    <div style={{ color: '#10b981', fontSize: '0.7rem', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>Remediation Suggestion</div>
                                    <pre style={{ ...preStyle, borderLeft: '3px solid #10b981', color: '#f3f4f6' }}>{aiAnalysis.fix}</pre>
                                </div>

                                <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textAlign: 'right', fontStyle: 'italic', marginTop: '0.5rem' }}>
                                    Engine: {aiAnalysis.provider} • Confidence Score: {aiAnalysis.confidence}
                                </div>
                            </>
                        ) : (
                            <div style={{ color: 'var(--danger)', textAlign: 'center', padding: '2rem', background: 'rgba(239,68,68,0.05)', borderRadius: '10px', border: '1px solid rgba(239,68,68,0.1)' }}>
                                ⚠️ {aiError || 'AI Analysis failed to load. Please ensure the backend server is running.'}
                                {aiError && <div style={{ fontSize: '0.75rem', marginTop: '0.5rem', color: 'var(--text-muted)' }}>Check that VITE_API_BASE is correctly set in Vercel.</div>}
                            </div>
                        )}
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
