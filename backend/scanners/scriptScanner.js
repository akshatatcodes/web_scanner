/**
 * Suspicious Script Detection Scanner
 * Analyzes JavaScript for obfuscation, untrusted sources, and malicious patterns.
 */

const fs = require('fs');
const path = require('path');

// Load data files
let trustedDomains = [];
let scriptIgnoreList = [];

try {
    const trustedData = JSON.parse(fs.readFileSync(path.join(__dirname, '../data/trustedDomains.json'), 'utf8'));
    trustedDomains = trustedData.trustedDomains;

    const ignoreData = JSON.parse(fs.readFileSync(path.join(__dirname, '../data/scriptIgnoreList.json'), 'utf8'));
    scriptIgnoreList = ignoreData.ignoreList;
} catch (err) {
    console.error('[ScriptScanner] Error loading data files:', err.message);
}

const MALICIOUS_PATTERNS = [
    { name: 'Crypto-miner', pattern: /(coinhive|cryptonight|miner\.js|cryptoo-js|web-miner)/i, riskScore: 3 },
    { name: 'Credit Card Skimmer', pattern: /(cardNumber|ccnum|cvv|expiry|paymentForm|checkout-form|checkout_form)/i, riskScore: 3 },
    { name: 'Obfuscation Pattern', pattern: /(eval\(atob\(|String\.fromCharCode\(|(\\x[0-9a-f]{2}){4,}|(\\u[0-9a-f]{4}){4,})/i, riskScore: 3 }
];

const RISKY_APIS = [
    { name: 'EVAL_USAGE', pattern: /\beval\s*\(/gi, riskScore: 3, label: 'eval() usage' },
    { name: 'DOCUMENT_WRITE', pattern: /document\.write\s*\(/gi, riskScore: 2, label: 'document.write() usage' },
    { name: 'INNER_HTML_ASSIGNMENT', pattern: /\.innerHTML\s*=/gi, riskScore: 2, label: 'innerHTML assignment' },
    { name: 'OUTER_HTML_ASSIGNMENT', pattern: /\.outerHTML\s*=/gi, riskScore: 2, label: 'outerHTML assignment' },
    { name: 'INSERT_ADJACENT_HTML', pattern: /\.insertAdjacentHTML\s*\(/gi, riskScore: 2, label: 'insertAdjacentHTML usage' },
    { name: 'TIMER_STRING_EXEC', pattern: /(setTimeout|setInterval)\s*\(\s*['"].*['"]\s*[,)]/gi, riskScore: 3, label: 'String-based timer' }
];

const DOM_XSS_SOURCES = [
    { name: 'LOCATION_HASH', pattern: /location\.hash/gi, label: 'location.hash' },
    { name: 'DOCUMENT_URL', pattern: /document\.URL/gi, label: 'document.URL' },
    { name: 'WINDOW_NAME', pattern: /window\.name/gi, label: 'window.name' },
    { name: 'POST_MESSAGE', pattern: /addEventListener\s*\(\s*['"]message['"]/gi, label: 'postMessage listener' }
];

function analyze(scripts) {
    const results = [];

    scripts.forEach(script => {
        const issues = [];
        let maxScore = 0;

        // Skip ignored domains
        if (script.src) {
            try {
                const domain = new URL(script.src).hostname;
                if (scriptIgnoreList.some(d => domain.includes(d))) return;
                
                // Check Unknown External Domain
                const isTrusted = trustedDomains.some(d => domain.includes(d));
                if (!isTrusted) {
                    issues.push({
                        type: 'Unknown External Script',
                        code: 'UNKNOWN_DOMAIN',
                        reason: `Script loaded from untrusted domain: ${domain}`,
                        riskScore: 2
                    });
                    maxScore = Math.max(maxScore, 2);
                }
            } catch (e) {}
        }

        // Analyze Inline Content or Script Content if available
        if (script.content) {
            // Check for malicious patterns
            MALICIOUS_PATTERNS.forEach(p => {
                if (p.pattern.test(script.content)) {
                    issues.push({
                        type: p.name,
                        code: 'MALICIOUS_PATTERN',
                        reason: `Detected ${p.name.toLowerCase()} signature`,
                        riskScore: p.riskScore,
                        line: findLineNumber(script.content, p.pattern)
                    });
                    maxScore = Math.max(maxScore, p.riskScore);
                }
            });

            // Check for risky APIs
            RISKY_APIS.forEach(api => {
                if (api.pattern.test(script.content)) {
                    issues.push({
                        type: 'Risky API Usage',
                        code: api.name,
                        reason: `Detected use of ${api.label}`,
                        riskScore: api.riskScore,
                        line: findLineNumber(script.content, api.pattern)
                    });
                    maxScore = Math.max(maxScore, api.riskScore);
                }
            });

            // Check for DOM XSS attack paths (Source + Sink)
            const hasSource = DOM_XSS_SOURCES.find(s => s.pattern.test(script.content));
            const hasSink = RISKY_APIS.filter(api => api.name !== 'TIMER_STRING_EXEC').find(api => api.pattern.test(script.content));

            if (hasSource && hasSink) {
                issues.push({
                    type: 'DOM XSS Risk',
                    code: 'DOM_XSS_PATH',
                    reason: `Potential attack path: ${hasSource.label} flow into ${hasSink.label}`,
                    riskScore: 3,
                    line: findLineNumber(script.content, hasSource.pattern)
                });
                maxScore = 3;
            }
        }

        if (issues.length > 0) {
            results.push({
                source: script.src || 'inline-script',
                issues,
                risk: getRiskLabel(maxScore),
                riskScore: maxScore
            });
        }
    });

    return results;
}

function findLineNumber(content, pattern) {
    try {
        const index = content.search(pattern);
        if (index === -1) return null;
        const lines = content.substring(0, index).split('\n');
        return lines.length;
    } catch (e) {
        return null;
    }
}

function getRiskLabel(score) {
    if (score >= 3) return 'HIGH';
    if (score >= 2) return 'MEDIUM';
    return 'LOW';
}

module.exports = { analyze };
