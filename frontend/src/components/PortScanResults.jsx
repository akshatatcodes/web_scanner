import React, { useState } from 'react';

const PortScanResults = ({ targetUrl }) => {
    const [permission, setPermission] = useState(false);
    const [isScanning, setIsScanning] = useState(false);
    const [scanResults, setScanResults] = useState(null);
    const [error, setError] = useState(null);

    const handleScan = async () => {
        if (!permission) {
            alert('Please check the authorization box to confirm you have legal permission to actively scan this target.');
            return;
        }
        setIsScanning(true);
        setError(null);
        setScanResults(null);
        try {
            const response = await fetch('http://localhost:5000/api/scan-ports', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: targetUrl, permission })
            });
            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Failed to scan ports');
            }
            const { jobId } = await response.json();
            
            const poll = setInterval(async () => {
                try {
                    const statusRes = await fetch(`http://localhost:5000/api/jobs/${jobId}`);
                    const statusData = await statusRes.json();
                    
                    if (statusData.state === 'completed') {
                        clearInterval(poll);
                        // Depending on what worker returns, it might be { portScan: results } or just results
                        const finalPorts = statusData.result.portScan !== undefined ? statusData.result.portScan : statusData.result;
                        setScanResults(finalPorts);
                        setIsScanning(false);
                    } else if (statusData.state === 'failed') {
                        clearInterval(poll);
                        setError(statusData.failedReason || 'Port scan failed.');
                        setIsScanning(false);
                    }
                } catch (err) {
                    clearInterval(poll);
                    setError('Error checking port scan status.');
                    setIsScanning(false);
                }
            }, 2000);
            
        } catch (err) {
            setError(err.message);
            setIsScanning(false);
        }
    };

    return (
        <div className="glass-panel result-card full-width fadeIn" style={{ marginTop: '1.5rem' }}>
            <div className="result-header">
                <span className="category-icon">🔌</span>
                <h3 className="result-title">Active Port Scan</h3>
                <span style={{ marginLeft: 'auto', fontSize: '0.75rem', color: 'var(--text-muted)', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', padding: '0.2rem 0.6rem', borderRadius: '12px', fontWeight: 700 }}>ACTIVE RECON</span>
            </div>

            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.6, margin: '0 0 1.5rem 0' }}>
                Active port scanning sends direct network requests to common service ports to identify open listening services.
                This action actively probes the target infrastructure and requires your authorization.
            </p>

            <div className="permission-box">
                <label className="permission-label">
                    <input
                        type="checkbox"
                        checked={permission}
                        onChange={(e) => setPermission(e.target.checked)}
                    />
                    I confirm I have <strong>legal authorization</strong> to actively scan this infrastructure.
                </label>
            </div>

            <button
                className={`port-scan-btn ${permission ? 'active' : ''}`}
                onClick={handleScan}
                disabled={isScanning}
                style={{ maxWidth: '260px' }}
            >
                {isScanning ? (
                    <><span className="btn-spinner"></span> Scanning Ports...</>
                ) : '🔍 Run Port Scan'}
            </button>

            {error && <div className="port-scan-error">{error}</div>}

            {scanResults && (
                <div className="port-scan-results fadeIn">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem', borderTop: '1px solid var(--border-color)', paddingTop: '1.5rem' }}>
                        <h4 className="xss-section-title" style={{ margin: 0 }}>
                            {scanResults.length > 0 ? `${scanResults.length} Open Services Detected` : 'No Open Ports Found'}
                        </h4>
                        <span style={{ marginLeft: 'auto', fontSize: '0.75rem', padding: '0.2rem 0.6rem', borderRadius: '12px', fontWeight: 700, background: scanResults.length > 0 ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)', color: scanResults.length > 0 ? 'var(--danger)' : 'var(--success)', border: `1px solid ${scanResults.length > 0 ? 'rgba(239,68,68,0.25)' : 'rgba(16,185,129,0.25)'}` }}>
                            {scanResults.length > 0 ? '⚠ EXPOSURE DETECTED' : '✓ ALL CLOSED'}
                        </span>
                    </div>
                    {scanResults.length > 0 ? (
                        <div className="port-grid">
                            {scanResults.map((res, i) => (
                                <div key={i} className="port-card">
                                    <div className="port-number">{res.port}</div>
                                    <div className="port-info">
                                        <span className="port-service">{res.service}</span>
                                        <span className="port-status open">OPEN</span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <p className="no-findings">No common ports are publicly accessible.</p>
                    )}
                </div>
            )}
        </div>
    );
};

export default PortScanResults;
