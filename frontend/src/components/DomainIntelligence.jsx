import React, { useState } from 'react';
import SecurityExplanation from './SecurityExplanation';

const DomainIntelligence = ({ domainIntel }) => {
    const [selectedIssue, setSelectedIssue] = useState(null);
    const [showAllSubdomains, setShowAllSubdomains] = useState(false);

    if (!domainIntel) return null;

    const { reputation, subdomains, dns } = domainIntel;
    const dnsIssues = (dns && dns.issues) || [];
    const dnsRecords = (dns && dns.records) || {};

    const getReputationStatus = () => {
        if (!reputation) return { icon: '❓', text: 'Unknown', class: 'status-unknown' };
        if (reputation.status === 'malicious') return { icon: '⚠️', text: 'Malicious', class: 'status-danger' };
        if (reputation.status === 'clean') return { icon: '✅', text: 'Clean Status', class: 'status-success' };
        return { icon: '❓', text: 'Unknown', class: 'status-unknown' };
    };

    const rep = getReputationStatus();

    // Map DNS issues to humanIssues format for SecurityExplanation
    const processedDnsIssues = dnsIssues.map(issue => ({
        ...issue,
        code: issue.code,
        details: {
            title: issue.issue,
            explanation: issue.description,
            impact: "Attackers can use this gap for phishing and email spoofing.",
            recommendation: issue.recommendation
        }
    }));

    const displayedSubdomains = showAllSubdomains ? subdomains : subdomains?.slice(0, 10);

    return (
        <div className="glass-panel result-card full-width fadeIn" style={{ marginTop: '1.5rem' }}>
            <div className="result-header">
                <span className="category-icon">🌐</span>
                <h3 className="result-title">Domain Intelligence & OSINT</h3>
            </div>

            <div className="intel-grid">
                {/* Reputation & Threat Analysis */}
                <div className="intel-section">
                    <h4 className="xss-section-title">Reputation Status</h4>
                    <div className={`reputation-card ${rep.class}`}>
                        <span className="rep-icon">{rep.icon}</span>
                        <div className="rep-info">
                            <span className="rep-status">{rep.text}</span>
                            <span className="rep-provider">Provider: Google Safe Browsing</span>
                        </div>
                    </div>
                    {reputation?.threats?.length > 0 && (
                        <div className="threat-list" style={{ marginTop: '1rem' }}>
                            {reputation.threats.map((t, i) => (
                                <div key={i} className="threat-tag">
                                    <span className="threat-type">{t.type}</span>
                                    <span className="threat-plat">{t.platform}</span>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* Subdomains */}
                    <h4 className="xss-section-title" style={{ marginTop: '2rem' }}>Subdomain Discovery</h4>
                    {subdomains && subdomains.length > 0 ? (
                        <div className="subdomain-explorer">
                            <div className="subdomain-tags">
                                {displayedSubdomains.map((sub, i) => (
                                    <span key={i} className="sub-tag">{sub}</span>
                                ))}
                            </div>
                            {subdomains.length > 10 && (
                                <button 
                                    className="show-more-btn"
                                    onClick={() => setShowAllSubdomains(!showAllSubdomains)}
                                >
                                    {showAllSubdomains ? 'Show Less' : `Show all ${subdomains.length} subdomains`}
                                </button>
                            )}
                        </div>
                    ) : (
                        <p className="no-findings">No public subdomains found via passive enumeration.</p>
                    )}
                </div>

                {/* DNS & Mail Security */}
                <div className="intel-section divider-left">
                    <h4 className="xss-section-title">DNS Security Matrix</h4>
                    <div className="dns-matrix">
                        {dnsRecords.A?.length > 0 && (
                            <div className="dns-record-row">
                                <span className="dns-type">A</span>
                                <div className="dns-vals">
                                    {dnsRecords.A.map((ip, i) => <code key={i}>{ip}</code>)}
                                </div>
                            </div>
                        )}
                        {dnsRecords.MX?.length > 0 && (
                            <div className="dns-record-row">
                                <span className="dns-type">MX</span>
                                <div className="dns-vals">
                                    {dnsRecords.MX.map((mx, i) => <code key={i}>{mx}</code>)}
                                </div>
                            </div>
                        )}
                        {dnsRecords.NS?.length > 0 && (
                            <div className="dns-record-row">
                                <span className="dns-type">NS</span>
                                <div className="dns-vals">
                                    {dnsRecords.NS.map((ns, i) => <code key={i}>{ns}</code>)}
                                </div>
                            </div>
                        )}
                    </div>

                    <h4 className="xss-section-title" style={{ marginTop: '2rem' }}>Protocol Forensics</h4>
                    <div className="xss-findings-list">
                        {processedDnsIssues.length === 0 ? (
                            <div className="protection-item pos">
                                <span className="prot-icon">✅</span>
                                <span className="prot-text">Anti-Spoofing Protocols (SPF/DMARC) Enabled</span>
                            </div>
                        ) : (
                            processedDnsIssues.map((issue, idx) => (
                                <div key={idx} className="protection-item neg">
                                    <span className="prot-icon">🚩</span>
                                    <div className="prot-content">
                                        <span className="prot-text">{issue.details.title}</span>
                                        <button 
                                            className="learn-more-link"
                                            onClick={() => setSelectedIssue(issue)}
                                        >
                                            Analysis
                                        </button>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            </div>

            {selectedIssue && (
                <SecurityExplanation 
                    issue={selectedIssue} 
                    onClose={() => setSelectedIssue(null)} 
                />
            )}
        </div>
    );
};

export default DomainIntelligence;
