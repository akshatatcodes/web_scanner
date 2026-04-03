/**
 * Professional Reporting Engine
 * Converts scan results into commercial-grade security assessment reports.
 */

const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

// Standardized Severity Levels
const SEVERITY = {
    CRITICAL: { label: 'Critical', color: '#dc2626', score: 10 },
    HIGH: { label: 'High', color: '#f97316', score: 7 },
    MEDIUM: { label: 'Medium', color: '#eab308', score: 4 },
    LOW: { label: 'Low', color: '#2563eb', score: 2 },
    INFO: { label: 'Info', color: '#64748b', score: 0 }
};

// OWASP Top 10 2021 Mapping
const OWASP_MAPPING = {
    'SQL_INJECTION': 'A03:2021-Injection',
    'COMMAND_INJECTION': 'A03:2021-Injection',
    'XSS_RISK': 'A03:2021-Injection',
    'MISSING_CSP': 'A05:2021-Security Misconfiguration',
    'IDOR_VULNERABILITY': 'A01:2021-Broken Access Control',
    'JWT_MISCONFIG': 'A02:2021-Cryptographic Failures',
    'SSRF_VULNERABILITY': 'A10:2021-Server-Side Request Forgery',
    'AUTH_BYPASS': 'A07:2021-Identification and Authentication Failures',
    'OPEN_REDIRECT': 'A03:2021-Injection',
    'CVE_VULNERABILITY': 'A06:2021-Vulnerable and Outdated Components'
};

/**
 * Calculates risk metrics based on scan results.
 */
function calculateMetrics(results) {
    const findings = [];
    
    // Aggregate all findings from various scanners
    if (results.vulnerabilities) {
        Object.entries(results.vulnerabilities).forEach(([tech, vulns]) => {
            vulns.forEach(v => {
                findings.push({ 
                    ...v, 
                    title: v.title || v.id || `${tech} Vulnerability`,
                    type: v.type || 'CVE_VULNERABILITY',
                    source: `Vulnerability Scanner (${tech})` 
                });
            });
        });
    }
    
    if (results.cookieSecurity) {
        results.cookieSecurity.forEach(c => {
            c.humanIssues.forEach(i => {
                findings.push({ 
                    type: i.code, 
                    severity: i.risk || 'LOW', 
                    title: i.details.title,
                    description: i.details.explanation,
                    recommendation: i.details.recommendation,
                    source: `Cookie: ${c.name}`
                });
            });
        });
    }

    if (results.suspiciousScripts) {
        results.suspiciousScripts.forEach(s => {
            s.humanIssues.forEach(i => {
                findings.push({
                    type: i.code,
                    severity: i.risk || 'LOW',
                    title: i.details.title,
                    description: i.details.explanation,
                    recommendation: i.details.recommendation,
                    source: `Script: ${s.source || 'Inline'}`
                });
            });
        });
    }

    // Add other findings (SQLi, IDOR, etc.)
    const directFindings = [
        { key: 'sqli', type: 'SQL_INJECTION', severity: 'HIGH', title: 'SQL Injection confirmed', defaultDescription: 'The scanner confirmed a SQL Injection vulnerability, allowing attackers to interfere with database queries.' },
        { key: 'cmdInjection', type: 'COMMAND_INJECTION', severity: 'HIGH', title: 'OS Command Injection confirmed', defaultDescription: 'The scanner discovered an OS Command Injection vulnerability, allowing attackers to execute arbitrary commands on the host operating system.' },
        { key: 'idors', type: 'IDOR_VULNERABILITY', severity: 'HIGH', title: 'IDOR Vulnerability', defaultDescription: 'An Insecure Direct Object Reference (IDOR) was found, which may allow unauthorized access to sensitive records.' },
        { key: 'ssrfFindings', type: 'SSRF_VULNERABILITY', severity: 'HIGH', title: 'SSRF Vulnerability', defaultDescription: 'A Server-Side Request Forgery vulnerability was observed, potentially allowing servers to be coerced into making arbitrary internal/external requests.' },
        { key: 'jwtIssues', type: 'JWT_MISCONFIG', severity: 'MEDIUM', title: 'JWT Security Issue', defaultDescription: 'A JSON Web Token (JWT) misconfiguration or weakness was detected.' },
        { key: 'adminPanels', type: 'AUTH_BYPASS', severity: 'MEDIUM', title: 'Admin Panel Exposed', defaultDescription: 'An administrative interface was exposed without adequate obfuscation or protection, potentially creating a lucrative target.' },
        { key: 'secretLeaks', type: 'JWT_MISCONFIG', severity: 'HIGH', title: 'Sensitive Information Leak', defaultDescription: 'API keys, tokens, or sensitive credentials were found exposed in the application files.' },
        { key: 'sensitiveData', type: 'MISSING_CSP', severity: 'MEDIUM', title: 'Sensitive Data Exposure', defaultDescription: 'Internal IP addresses, emails, or cloud storage URLs were found in the source code.' },
        { key: 'openRedirects', type: 'OPEN_REDIRECT', severity: 'LOW', title: 'Open Redirect Vulnerability', defaultDescription: 'A parameter allows the application to redirect users to external arbitrary URLs without validation.' },
        { key: 'corsIssues', type: 'MISSING_CSP', severity: 'LOW', title: 'Permissive CORS Configuration', defaultDescription: 'Cross-Origin Resource Sharing is configured permissively, potentially allowing unauthorized domains to read sensitive data.' },
        { key: 'authBypasses', type: 'AUTH_BYPASS', severity: 'CRITICAL', title: 'Authorization Bypass', defaultDescription: 'The scanner identified a flaw allowing authentication or authorization checks to be bypassed.' },
        { key: 'directories', type: 'MISSING_CSP', severity: 'LOW', title: 'Open Directory / File Exposure', defaultDescription: 'A sensitive directory or file backup was discovered on the server.' },
        { key: 'hiddenEndpoints', type: 'MISSING_CSP', severity: 'LOW', title: 'Hidden API / Status Endpoint', defaultDescription: 'An internal or undocumented API endpoint was discovered.' },
        { key: 'graphqlFindings', type: 'MISSING_CSP', severity: 'LOW', title: 'GraphQL Introspection / Exposure', defaultDescription: 'The GraphQL endpoint allows introspection or displays overly verbose schema errors.' },
        { key: 'rateLimits', type: 'MISSING_CSP', severity: 'LOW', title: 'Missing Rate Limiting', defaultDescription: 'An authentication or sensitive endpoint is missing rate limiting protections, making it vulnerable to brute-force attacks.' },
    ];

    directFindings.forEach(df => {
        if (results[df.key] && results[df.key].length > 0) {
            const grouped = new Map();
            results[df.key].forEach(f => {
                const ep = f.url || f.endpoint;
                if (!ep) return;
                let baseUrl = ep;
                try {
                    const u = new URL(ep);
                    baseUrl = u.origin + u.pathname;
                } catch(e) {
                    baseUrl = ep.split('?')[0];
                }
                if (!grouped.has(baseUrl)) {
                    grouped.set(baseUrl, {
                        ...df,
                        description: f.description || f.reason || f.details || df.defaultDescription,
                        endpoints: new Set([ep]),
                        payloads: new Set(f.payload ? [f.payload] : []),
                        evidenceAcc: [f.evidence || f.details || ep]
                    });
                } else {
                    const existing = grouped.get(baseUrl);
                    existing.endpoints.add(ep);
                    if (f.payload) existing.payloads.add(f.payload);
                    const ev = f.evidence || f.details || ep;
                    // Avoid duplicating exact same evidence blocks
                    if (!existing.evidenceAcc.includes(ev) && typeof ev === 'string') {
                        existing.evidenceAcc.push(ev);
                    }
                }
            });

            grouped.forEach((g, baseUrl) => {
                const epList = Array.from(g.endpoints);
                const payloadList = Array.from(g.payloads);
                
                let combinedEvidence = g.evidenceAcc.map(ev => typeof ev === 'object' ? JSON.stringify(ev, null, 2) : ev).join('\\n--- \\n');
                
                findings.push({
                    ...df,
                    description: g.description,
                    endpoint: epList.length > 1 ? `${baseUrl} (and ${epList.length - 1} related endpoints)` : epList[0],
                    payload: payloadList.length > 0 ? payloadList.join('\\n') : null,
                    evidence: epList.length > 1 ? `Vulnerable Endpoints:\\n${epList.join('\\n')}\\n\\nEvidence Details:\\n${combinedEvidence}` : combinedEvidence,
                    allEndpoints: epList
                });
            });
        }
    });

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => {
        const sev = (f.severity || 'INFO').toUpperCase();
        if (counts[sev] !== undefined) counts[sev]++;
    });

    const total = findings.length;
    let riskScore = 0;
    if (counts.CRITICAL > 0) riskScore = 100;
    else if (counts.HIGH > 0) riskScore = 75;
    else if (counts.MEDIUM > 0) riskScore = 45;
    else riskScore = 15;

    const riskLevel = riskScore >= 75 ? 'HIGH' : (riskScore >= 40 ? 'MEDIUM' : 'LOW');

    return {
        total,
        counts,
        riskScore,
        riskLevel,
        findings,
        attackSurface: results.scanContext?.stats?.uniqueEndpoints || 0,
        scanDuration: results.scanDuration,
        timestamp: results.timestamp,
        target: results.target || results.url,
        sslInfo: results.sslInfo,
        waf: results.waf,
        domainIntel: results.domainIntel,
        securityHeaders: results.securityHeaders,
        technologies: results.technologies
    };
}

/**
 * Generates an HTML report.
 */
function generateHtml(results) {
    const metrics = calculateMetrics(results);
    const date = new Date(metrics.timestamp).toLocaleString();
    
    const severityRows = Object.entries(metrics.counts).map(([sev, count]) => `
        <div class="metric-card">
            <div class="metric-label" style="color: ${SEVERITY[sev].color}">${SEVERITY[sev].label}</div>
            <div class="metric-value">${count}</div>
        </div>
    `).join('');

    // Group findings by category for technical section
    const groupedFindings = metrics.findings.reduce((acc, f) => {
        const cat = OWASP_MAPPING[f.type] || 'A00:2021-General Security';
        if (!acc[cat]) acc[cat] = [];
        acc[cat].push(f);
        return acc;
    }, {});
    const technicalSections = Object.entries(groupedFindings).map(([category, findings]) => `
        <div class="category-block">
            <h3 class="category-title">${category}</h3>
            ${findings.map(f => {
                const sev = (f.severity || 'INFO').toUpperCase();
                return `
                <div class="finding-card ${sev.toLowerCase()}">
                    <div class="finding-header">
                        <span class="sev-badge" style="background: ${SEVERITY[sev].color}">${SEVERITY[sev].label}</span>
                        <span class="finding-title">${f.title || 'Security Finding'}</span>
                    </div>
                    <div class="finding-body">
                        <p><strong>Observation:</strong> ${f.description || f.reason || 'No description provided.'}</p>
                        <p><strong>Technical Context:</strong> <code>${f.source || f.endpoint || results.target}</code></p>
                        ${f.recommendation ? `<p><strong>Remediation:</strong> ${f.recommendation}</p>` : ''}
                        
                        ${(f.payload || f.evidence) ? `
                        <div class="exploit-proof">
                            <div class="proof-header">Forensic Evidence & Exploit Proof</div>
                            ${f.endpoint ? `<p><strong>Affected URL:</strong> <code>${f.endpoint}</code></p>` : ''}
                            ${f.payload ? `<p><strong>Payload:</strong> <code class="payload">${escapeHtml(f.payload)}</code></p>` : ''}
                            ${f.evidence ? `<pre class="evidence">${escapeHtml(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2))}</pre>` : ''}
                        </div>
                        ` : ''}
                    </div>
                </div>`;
            }).join('')}
        </div>
    `).join('');

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Security Assessment Report - ${metrics.target}</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
            :root {
                --primary: #0f172a;
                --primary-light: #1e293b;
                --accent: #3b82f6;
                --text-dark: #0f172a;
                --text-muted: #64748b;
                --bg: #f8fafc;
                --white: #ffffff;
                --border: #e2e8f0;
            }
            body { 
                font-family: 'Inter', sans-serif; 
                line-height: 1.5; 
                color: var(--text-dark); 
                background: var(--bg);
                margin: 0;
                padding: 0;
            }
            .page {
                max-width: 1000px;
                margin: 0 auto;
                background: var(--white);
                min-height: 297mm;
                padding: 60px 80px;
                box-shadow: 0 0 20px rgba(0,0,0,0.05);
            }
            
            /* Header & Branding */
            .report-header {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                margin-bottom: 60px;
                border-bottom: 4px solid var(--primary);
                padding-bottom: 30px;
            }
            .brand { display: flex; align-items: center; gap: 15px; }
            .logo-icon { font-size: 42px; }
            .logo-text { font-size: 24px; font-weight: 800; color: var(--primary); letter-spacing: -1px; }
            .logo-text span { color: var(--accent); }
            
            .meta-info { text-align: right; }
            .meta-label { font-size: 10px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 2px; }
            .meta-value { font-size: 14px; font-weight: 600; margin-bottom: 12px; }

            /* Executive Banner */
            .exec-banner {
                background: var(--primary);
                color: var(--white);
                padding: 40px;
                border-radius: 12px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 50px;
            }
            .exec-title h1 { margin: 0; font-size: 32px; font-weight: 800; letter-spacing: -1px; }
            .exec-title p { margin: 10px 0 0 0; opacity: 0.7; font-size: 16px; }
            
            .risk-meter {
                text-align: center;
                border: 4px solid rgba(255,255,255,0.1);
                padding: 20px 30px;
                border-radius: 16px;
                background: rgba(255,255,255,0.03);
            }
            .risk-score { font-size: 48px; font-weight: 800; line-height: 1; }
            .risk-lvl { font-size: 14px; font-weight: 700; text-transform: uppercase; margin-top: 5px; padding: 4px 12px; border-radius: 4px; }

            /* Section Styling */
            .section-h {
                font-size: 11px;
                font-weight: 800;
                text-transform: uppercase;
                letter-spacing: 2px;
                color: var(--accent);
                margin: 60px 0 20px 0;
                display: flex;
                align-items: center;
                gap: 15px;
            }
            .section-h::after { content: ""; flex: 1; height: 1px; background: var(--border); }

            /* Risk Matrix */
            .matrix-container {
                display: flex;
                gap: 40px;
                align-items: center;
                margin-bottom: 40px;
                background: #f1f5f9;
                padding: 30px;
                border-radius: 12px;
            }
            .matrix-grid {
                display: grid;
                grid-template-columns: repeat(5, 40px);
                gap: 4px;
            }
            .matrix-cell { width: 40px; height: 40px; border-radius: 4px; }
            .m-low { background: #dcfce7; }
            .m-med { background: #fef9c3; }
            .m-high { background: #ffedd5; }
            .m-crit { background: #fee2e2; }
            .m-active { border: 3px solid var(--primary); box-shadow: 0 0 10px rgba(0,0,0,0.2); position: relative; }
            .m-active::after { content: "!"; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-weight: 900; }

            .matrix-desc { flex: 1; }
            .matrix-desc h3 { margin: 0 0 10px 0; font-size: 18px; }
            .matrix-desc p { margin: 0; color: var(--text-muted); font-size: 14px; }

            /* Metrics Grid */
            .metrics-grid {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 20px;
                margin-bottom: 40px;
            }
            .metric-card {
                padding: 20px;
                border: 1px solid var(--border);
                border-radius: 8px;
                text-align: center;
            }
            .metric-value { font-size: 28px; font-weight: 800; color: var(--primary); }
            .metric-label { font-size: 10px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-top: 5px; }

            /* Finding Blocks */
            .category-block { margin-bottom: 40px; }
            .category-title { font-size: 18px; font-weight: 700; margin-bottom: 20px; color: var(--primary); border-bottom: 1px solid var(--border); padding-bottom: 10px; }
            
            .finding-card {
                border-left: 6px solid #ddd;
                padding: 25px;
                margin-bottom: 25px;
                background: #fff;
                box-shadow: 0 2px 10px rgba(0,0,0,0.02);
                border-radius: 0 8px 8px 0;
            }
            .finding-card.critical { border-left-color: #dc2626; background: #fff1f2; }
            .finding-card.high { border-left-color: #f97316; background: #fff7ed; }
            .finding-card.medium { border-left-color: #eab308; background: #fefce8; }
            .finding-card.low { border-left-color: #2563eb; background: #eff6ff; }

            .finding-header { display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }
            .sev-badge { color: white; padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 800; text-transform: uppercase; }
            .finding-title { font-size: 16px; font-weight: 700; color: var(--primary); flex: 1; }

            .finding-body p { margin: 8px 0; font-size: 14px; }
            .finding-body code { font-family: 'JetBrains Mono', monospace; font-size: 13px; background: rgba(0,0,0,0.05); padding: 2px 6px; border-radius: 4px; }

            .exploit-proof {
                margin-top: 20px;
                background: var(--white);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 20px;
            }
            .proof-header { font-size: 11px; font-weight: 800; text-transform: uppercase; color: var(--text-muted); margin-bottom: 15px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
            
            pre.evidence {
                background: #0f172a;
                color: #e2e8f0;
                padding: 20px;
                border-radius: 6px;
                font-size: 12px;
                overflow-x: auto;
                margin-top: 10px;
            }
            .payload { color: #f43f5e; font-weight: 700; background: transparent !important; padding: 0 !important; }

            .footer {
                margin-top: 80px;
                text-align: center;
                font-size: 11px;
                color: var(--text-muted);
                border-top: 1px solid var(--border);
                padding-top: 40px;
            }

            @media print {
                body { background: white; }
                .page { box-shadow: none; padding: 0; }
                .finding-card { page-break-inside: avoid; }
            }
        </style>
    </head>
    <body>
        <div class="page">
            <div class="report-header">
                <div class="brand">
                    <div class="logo-icon">🛡️</div>
                    <div class="logo-text">Vulnexa <span>PRO</span></div>
                </div>
                <div class="meta-info">
                    <div class="meta-label">Assessment Target</div>
                    <div class="meta-value">${metrics.target}</div>
                    <div class="meta-label">Scan Completion Date</div>
                    <div class="meta-value">${date}</div>
                </div>
            </div>

            <div class="exec-banner">
                <div class="exec-title">
                    <h1>Executive Summary</h1>
                    <p>Proprietary Security Exposure Assessment for ${metrics.target.split('//')[1] || metrics.target}</p>
                </div>
                <div class="risk-meter">
                    <div class="risk-score">${metrics.riskScore}<span>/100</span></div>
                    <div class="risk-lvl" style="background: ${SEVERITY[metrics.riskLevel].color}">POSTURE: ${metrics.riskLevel}</div>
                </div>
            </div>

            <div class="section-h">Risk Posture Analysis</div>
            <div class="matrix-container">
                <div class="matrix-grid">
                    ${Array(25).fill(0).map((_, i) => {
                        let cls = 'm-low';
                        if (i < 5) cls = 'm-crit';
                        else if (i < 10) cls = 'm-high';
                        else if (i < 15) cls = 'm-med';
                        
                        // Highlight active risk level cell (simplified mapping)
                        const isActive = (metrics.riskLevel === 'HIGH' && i === 6) || 
                                         (metrics.riskLevel === 'CRITICAL' && i === 2) ||
                                         (metrics.riskLevel === 'MEDIUM' && i === 12) ||
                                         (metrics.riskLevel === 'LOW' && i === 22);
                        
                        return `<div class="matrix-cell ${cls} ${isActive ? 'm-active' : ''}"></div>`;
                    }).join('')}
                </div>
                <div class="matrix-desc">
                    <h3>Risk Impact vs. Probability</h3>
                    <p>Based on our automated analysis, the target application demonstrates a <strong>${metrics.riskLevel}</strong> operational risk profile. This score integrates vulnerability counts, exploitability, and potential business impact of confirmed threats.</p>
                </div>
            </div>

            <div class="metrics-grid">
                ${severityRows}
                <div class="metric-card">
                    <div class="metric-value">${metrics.attackSurface}</div>
                    <div class="metric-label">Identified Endpoints</div>
                </div>
            </div>

            <div class="section-h">Infrastructure & Reconnaissance Context</div>
            <div class="recon-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 40px;">
                ${metrics.sslInfo ? `
                <div class="recon-card" style="background: #fff; padding: 20px; border: 1px solid var(--border); border-radius: 8px;">
                    <h3 style="margin-top:0; font-size:14px; color:var(--primary);"><span style="margin-right:8px;">🔒</span> SSL/TLS Configuration</h3>
                    <div style="font-size: 13px; line-height: 1.6;">
                        <strong>Status:</strong> <span style="color: ${metrics.sslInfo.valid ? '#10b981' : '#ef4444'}">${metrics.sslInfo.valid ? 'Valid & Secure' : 'Insecure / Expired'}</span><br>
                        <strong>Protocol:</strong> ${metrics.sslInfo.protocol || 'Not Available'}<br>
                        <strong>Issuer:</strong> ${metrics.sslInfo.issuer || 'Not Available'}<br>
                        <strong>Expires In:</strong> ${metrics.sslInfo.remainingDays || 0} days
                    </div>
                </div>
                ` : ''}
                
                ${metrics.waf ? `
                <div class="recon-card" style="background: #fff; padding: 20px; border: 1px solid var(--border); border-radius: 8px;">
                    <h3 style="margin-top:0; font-size:14px; color:var(--primary);"><span style="margin-right:8px;">🛡️</span> Edge Defense / WAF</h3>
                    <div style="font-size: 13px; line-height: 1.6;">
                        <strong>Detected WAF:</strong> ${metrics.waf.name || 'Unknown / None Detected'}<br>
                        <strong>Confidence:</strong> ${metrics.waf.confidence ? `${metrics.waf.confidence}%` : 'N/A'}<br>
                        <strong>Evasion Status:</strong> ${metrics.waf.name ? 'Active' : 'Not Required'}
                    </div>
                </div>
                ` : ''}

                ${metrics.domainIntel && metrics.domainIntel.asn ? `
                <div class="recon-card" style="background: #fff; padding: 20px; border: 1px solid var(--border); border-radius: 8px;">
                    <h3 style="margin-top:0; font-size:14px; color:var(--primary);"><span style="margin-right:8px;">🌐</span> Cloud / ASN Intelligence</h3>
                    <div style="font-size: 13px; line-height: 1.6;">
                        <strong>Organization:</strong> ${metrics.domainIntel.asn.organization || 'N/A'}<br>
                        <strong>Network Route:</strong> ${metrics.domainIntel.asn.route || 'N/A'}<br>
                        <strong>ASN:</strong> ${metrics.domainIntel.asn.asn || 'N/A'}
                    </div>
                </div>
                ` : ''}
                
                ${metrics.securityHeaders ? `
                <div class="recon-card" style="background: #fff; padding: 20px; border: 1px solid var(--border); border-radius: 8px;">
                    <h3 style="margin-top:0; font-size:14px; color:var(--primary);"><span style="margin-right:8px;">📝</span> HTTP Security Headers</h3>
                    <div style="font-size: 13px; line-height: 1.6;">
                        <strong>Strict-Transport-Security:</strong> ${metrics.securityHeaders['Strict-Transport-Security'] || 'Missing'}<br>
                        <strong>Content-Security-Policy:</strong> ${metrics.securityHeaders['Content-Security-Policy'] || 'Missing'}<br>
                        <strong>X-Frame-Options:</strong> ${metrics.securityHeaders['X-Frame-Options'] || 'Missing'}
                    </div>
                </div>
                ` : ''}
            </div>

            <div class="section-h">Security Posture & Configuration Checks</div>
            <div style="background: #fff; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 40px; overflow: hidden;">
                <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 13px;">
                    <thead style="background: #f8fafc; border-bottom: 1px solid var(--border);">
                        <tr>
                            <th style="padding: 12px 20px; font-weight: 600; color: var(--text-muted);">Security Control</th>
                            <th style="padding: 12px 20px; font-weight: 600; color: var(--text-muted);">Status</th>
                            <th style="padding: 12px 20px; font-weight: 600; color: var(--text-muted);">Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr style="border-bottom: 1px solid var(--border);">
                            <td style="padding: 15px 20px; font-weight: 500;">Transport Security (SSL/TLS)</td>
                            <td style="padding: 15px 20px;">${metrics.sslInfo && metrics.sslInfo.valid ? '<span style="color: #10b981; font-weight: 600;">✅ Secure</span>' : '<span style="color: #ef4444; font-weight: 600;">❌ Insecure</span>'}</td>
                            <td style="padding: 15px 20px; color: var(--text-muted);">${metrics.sslInfo && metrics.sslInfo.valid ? 'Valid certificate installed and served over HTTPS.' : 'Missing or expired SSL certificate. Data in transit is vulnerable.'}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid var(--border);">
                            <td style="padding: 15px 20px; font-weight: 500;">Directory Listing Exposure</td>
                            <td style="padding: 15px 20px;">${metrics.findings.some(f => f.key === 'directories') ? '<span style="color: #ef4444; font-weight: 600;">❌ Vulnerable</span>' : '<span style="color: #10b981; font-weight: 600;">✅ Secure</span>'}</td>
                            <td style="padding: 15px 20px; color: var(--text-muted);">${metrics.findings.some(f => f.key === 'directories') ? 'Sensitive directories or files are publicly accessible.' : 'No exposed internal directories detected.'}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid var(--border);">
                            <td style="padding: 15px 20px; font-weight: 500;">HTTP Security Headers</td>
                            <td style="padding: 15px 20px;">${metrics.securityHeaders && Object.values(metrics.securityHeaders).some(v => v !== 'Missing' && v !== 'Not Enabled') ? '<span style="color: #10b981; font-weight: 600;">✅ Hardened</span>' : '<span style="color: #eab308; font-weight: 600;">⚠️ Weak</span>'}</td>
                            <td style="padding: 15px 20px; color: var(--text-muted);">${metrics.securityHeaders && Object.values(metrics.securityHeaders).some(v => v !== 'Missing' && v !== 'Not Enabled') ? 'Modern security headers (CSP, HSTS) are actively enforced.' : 'Basic security headers are missing, increasing risk of XSS and clickjacking.'}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid var(--border);">
                            <td style="padding: 15px 20px; font-weight: 500;">Admin / Default Panel Protection</td>
                            <td style="padding: 15px 20px;">${metrics.findings.some(f => f.key === 'adminPanels') ? '<span style="color: #ef4444; font-weight: 600;">❌ Exposed</span>' : '<span style="color: #10b981; font-weight: 600;">✅ Secure</span>'}</td>
                            <td style="padding: 15px 20px; color: var(--text-muted);">${metrics.findings.some(f => f.key === 'adminPanels') ? 'A default administrative interface is accessible from the internet.' : 'No easily guessable admin panels or login portals found.'}</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="section-h">Technical Findings & Forensics</div>
            ${technicalSections.length > 0 ? technicalSections : '<p style="text-align: center; padding: 80px; color: var(--text-muted); background: #f8fafc; border-radius: 12px;">No automated vulnerabilities were identified in this session.</p>'}
            
            ${(results.attackChains && results.attackChains.length > 0) ? `
            <div class="category-block" style="border: 2px solid #ef4444; border-radius: 8px; padding: 25px; background: #fff1f2; margin-top: 40px; page-break-before: always;">
                <h3 style="color: #b91c1c; font-size: 20px; display: flex; align-items: center; gap: 10px; margin-top: 0; margin-bottom: 20px;">
                    🧨 Chained Exploit Paths (Attack Graph)
                </h3>
                <p style="color: #991b1b; font-size: 14px; margin-bottom: 25px;">
                    The AI behavioral engine discovered the following multi-stage exploitation vectors where chained vulnerabilities lead to critical compromise.
                </p>
                ${results.attackChains.map(chain => `
                    <div style="background: #fff; padding: 20px; border-radius: 6px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 20px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                            <span style="font-weight: 800; color: #b91c1c; font-size: 16px;">${chain.name}</span>
                            <span style="background: #ef4444; color: white; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: bold;">
                                ${chain.severity} (Confidence: ${(chain.confidence * 100).toFixed(0)}%)
                            </span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px; flex-wrap: wrap;">
                            ${chain.path.map((step, i) => `
                                <span style="background: #f1f5f9; border: 1px solid #cbd5e1; color: #334155; padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: bold;">${step}</span>
                                ${i < chain.path.length - 1 ? '<span style="color: #9ca3af; font-weight: bold;">→</span>' : ''}
                            `).join('')}
                        </div>
                        <p style="font-size: 13px; color: #4b5563; line-height: 1.6; margin: 0;">${chain.description}</p>
                    </div>
                `).join('')}
            </div>` : ''}

            ${(results.suspiciousScripts && results.suspiciousScripts.length > 0) ? `
            <div class="category-block" style="margin-top: 40px;">
                <h3 class="category-title">Suspicious Scripts & Code execution Risks</h3>
                ${results.suspiciousScripts.map(script => `
                    <div style="background: #fff; border: 1px solid #e2e8f0; padding: 20px; border-radius: 8px; margin-bottom: 15px;">
                        <div style="font-weight: bold; margin-bottom: 10px; word-break: break-all; font-size: 13px; color: var(--primary);">Source: <code style="background: #f1f5f9; padding: 2px 6px; border-radius: 4px;">${script.source || 'Inline Content'}</code></div>
                        ${script.humanIssues.map(issue => `
                            <div style="padding: 12px; background: #f8fafc; border-left: 4px solid #f59e0b; margin-top: 10px; font-size: 13px;">
                                <strong style="color: #b45309;">${issue.details.title}</strong>: ${issue.details.explanation}
                            </div>
                        `).join('')}
                    </div>
                `).join('')}
            </div>` : ''}

            ${(results.domainIntel && (results.domainIntel.jsRecon || results.domainIntel.githubRecon)) ? `
            <div class="category-block" style="margin-top: 40px; background: #0f172a; color: white; padding: 30px; border-radius: 12px; page-break-inside: avoid;">
                <h3 style="color: #38bdf8; font-size: 18px; margin-top: 0; margin-bottom: 25px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 15px;">🕵️ Hacker OSINT & Intelligence Mining</h3>
                
                ${results.domainIntel.jsRecon ? `
                <div style="margin-top: 20px;">
                    <h4 style="color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px;">JavaScript Analysis</h4>
                    <div style="display: flex; gap: 30px; font-size: 14px;">
                        <div><strong style="color: #e2e8f0;">Endpoints Found:</strong> <span style="color: #38bdf8">${results.domainIntel.jsRecon.endpoints?.length || 0}</span></div>
                        <div><strong style="color: #e2e8f0;">Secrets Leaked:</strong> <span style="color: ${results.domainIntel.jsRecon.secrets?.length > 0 ? '#ef4444' : '#10b981'}; font-weight: bold;">${results.domainIntel.jsRecon.secrets?.length || 0}</span></div>
                    </div>
                </div>
                ` : ''}

                ${results.domainIntel.githubRecon ? `
                <div style="margin-top: 25px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 25px;">
                    <h4 style="color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px;">GitHub Exposure</h4>
                    <div style="font-size: 14px; color: #cbd5e1;">
                        Found <strong style="color: white">${results.domainIntel.githubRecon.repositories?.length || 0}</strong> related repositories and <strong style="color: ${results.domainIntel.githubRecon.leaks?.length > 0 ? '#ef4444' : 'white'}">${results.domainIntel.githubRecon.leaks?.length || 0}</strong> potential code leaks.
                    </div>
                </div>
                ` : ''}
                
                ${results.behaviorProfiling ? `
                <div style="margin-top: 25px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 25px;">
                    <h4 style="color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px;">Behavioral Engine Profiler</h4>
                    <div style="font-size: 14px; color: #cbd5e1; line-height: 1.6;">
                        Sent <strong style="color: white">${results.behaviorProfiling.payloadsSent || 0}</strong> blind payloads and confirmed <strong style="color: ${results.behaviorProfiling.anomalies?.length > 0 ? '#ef4444' : '#10b981'}">${results.behaviorProfiling.anomalies?.length || 0}</strong> behavioral anomalies via timing and length variance mapping.
                    </div>
                </div>
                ` : ''}
            </div>` : ''}

            <div class="footer">
                <strong>CONFIDENTIAL DOCUMENT</strong><br>
                This report contains sensitive security findings. Access should be restricted to authorized technical management.<br>
                &copy; ${new Date().getFullYear()} Vulnexa Security Systems. All rights reserved. Made by Akshat Jain.
            </div>
        </div>
    </body>
    </html>
    `;
}

/**
 * Generates a PDF report using Puppeteer.
 */
async function generatePdf(results) {
    const html = generateHtml(results);
    const browser = await puppeteer.launch({
        headless: "new",
        args: ["--no-sandbox", "--disable-setuid-sandbox"]
    });
    
    try {
        const page = await browser.newPage();
        await page.setContent(html, { waitUntil: 'networkidle0' });
        
        // Ensure PDF directory exists if we decide to save it later
        // For now, we return the buffer
        const pdfBuffer = await page.pdf({
            format: 'A4',
            margin: { top: '20px', bottom: '20px', left: '20px', right: '20px' },
            printBackground: true,
            displayHeaderFooter: true,
            headerTemplate: '<div></div>',
            footerTemplate: `
                <div style="font-size: 8px; width: 100%; text-align: center; color: #cbd5e1; padding: 10px 0;">
                    Page <span class="pageNumber"></span> of <span class="totalPages"></span> | Confidential Report
                </div>
            `
        });
        
        return pdfBuffer;
    } finally {
        await browser.close();
    }
}

/**
 * Escapes HTML characters to prevent XSS.
 */
function escapeHtml(text) {
    if (typeof text !== 'string') return text;
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

module.exports = {
    calculateMetrics,
    generateHtml,
    generatePdf
};
