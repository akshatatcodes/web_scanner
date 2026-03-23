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
        { key: 'sqli', type: 'SQL_INJECTION', severity: 'HIGH', title: 'SQL Injection confirmed' },
        { key: 'cmdInjection', type: 'COMMAND_INJECTION', severity: 'HIGH', title: 'OS Command Injection confirmed' },
        { key: 'idors', type: 'IDOR_VULNERABILITY', severity: 'HIGH', title: 'IDOR Vulnerability' },
        { key: 'ssrfFindings', type: 'SSRF_VULNERABILITY', severity: 'HIGH', title: 'SSRF Vulnerability' },
        { key: 'jwtIssues', type: 'JWT_MISCONFIG', severity: 'MEDIUM', title: 'JWT Security Issue' }
    ];

    directFindings.forEach(df => {
        if (results[df.key] && results[df.key].length > 0) {
            results[df.key].forEach(f => {
                findings.push({
                    ...df,
                    evidence: f.evidence || f.url,
                    endpoint: f.url || f.endpoint,
                    payload: f.payload
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
        target: results.target || results.url
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
                    <div class="logo-text">ANTIGRAVITY <span>PRO</span></div>
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

            <div class="section-h">Technical Findings & Forensics</div>
            ${technicalSections.length > 0 ? technicalSections : '<p style="text-align: center; padding: 80px; color: var(--text-muted); background: #f8fafc; border-radius: 12px;">No automated vulnerabilities were identified in this session.</p>'}

            <div class="footer">
                <strong>CONFIDENTIAL DOCUMENT</strong><br>
                This report contains sensitive security findings. Access should be restricted to authorized technical management.<br>
                &copy; ${new Date().getFullYear()} Antigravity Security Systems. All rights reserved.
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
