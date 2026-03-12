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
    { name: 'Obfuscation Pattern', pattern: /(eval\(atob\(|String\.fromCharCode\(|\\x[0-9a-f]{2}|\\u[0-9a-f]{4})/i, riskScore: 3 }
];

const RISKY_APIS = [
    { name: 'Dangerous Execution', pattern: /eval\(/, riskScore: 3 },
    { name: 'Document Manipulation', pattern: /document\.write\(/, riskScore: 2 },
    { name: 'Dynamic Script Injection', pattern: /document\.createElement\(['"]script['"]\)/, riskScore: 2 }
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
                        riskScore: p.riskScore
                    });
                    maxScore = Math.max(maxScore, p.riskScore);
                }
            });

            // Check for risky APIs
            RISKY_APIS.forEach(api => {
                if (api.pattern.test(script.content)) {
                    issues.push({
                        type: 'Risky API Usage',
                        code: 'RISKY_API',
                        reason: `Detected use of ${api.name.toLowerCase()} APIs`,
                        riskScore: api.riskScore
                    });
                    maxScore = Math.max(maxScore, api.riskScore);
                }
            });
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

function getRiskLabel(score) {
    if (score >= 3) return 'HIGH';
    if (score >= 2) return 'MEDIUM';
    return 'LOW';
}

module.exports = { analyze };
