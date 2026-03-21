/**
 * wafScanner.js - PRO WAF Detection & Fingerprinting
 * Detects security filters using multi-signal analysis (Headers, Body, Behavior).
 */
const axios = require('axios');

const WAF_SIGNATURES = {
    CLOUDFLARE: {
        name: 'Cloudflare',
        headers: ['cf-ray', 'cf-request-id', 'cf-cache-status', 'server: cloudflare'],
        body: ['cloudflare-nginx', 'cf-browser-verification']
    },
    AKAMAI: {
        name: 'Akamai',
        headers: ['x-akamai-request-id', 'akamai-ghost', 'x-akamai-transformed'],
        body: ['akamai-error', 'akamai-security-page']
    },
    AWS_WAF: {
        name: 'AWS WAF',
        headers: ['x-amzn-requestid'],
        body: ['aws-waf', 'waf-blocked']
    },
    IMPERVA: {
        name: 'Imperva',
        headers: ['x-iinfo', 'incap_ses', 'visid_incap'],
        body: ['incapsula', 'imperva']
    },
    MODSECURITY: {
        name: 'ModSecurity',
        headers: ['server: mod_security', 'x-mod-security'],
        body: ['modsecurity', 'bad request']
    }
};

/**
 * Perform WAF Detection & Profiling
 */
async function detectWaf(url) {
    console.log(`[WAF Scanner] Profiling target: ${url}`);
    const results = {
        detected: false,
        name: 'None',
        confidence: 0,
        signals: [],
        behavior: {
            blockedMalicious: false,
            rateLimited: false
        }
    };

    try {
        // 1. Initial Discovery (Normal Request)
        const response = await axios.get(url, { validateStatus: false, timeout: 5000 });
        const headers = response.headers;
        const body = (typeof response.data === 'string') ? response.data.toLowerCase() : '';

        // Check for signatures
        for (const [key, waf] of Object.entries(WAF_SIGNATURES)) {
            let matches = 0;
            
            // Header signals
            waf.headers.forEach(h => {
                const [k, v] = h.includes(':') ? h.split(': ') : [h, null];
                if (headers[k.toLowerCase()] && (!v || headers[k.toLowerCase()].includes(v))) {
                    matches += 1;
                    results.signals.push(`Header: ${h}`);
                }
            });

            // Body signals
            waf.body.forEach(b => {
                if (body.includes(b)) {
                    matches += 1;
                    results.signals.push(`Body Pattern: ${b}`);
                }
            });

            if (matches > 0) {
                results.detected = true;
                results.name = waf.name;
                results.confidence = Math.min(0.9, matches / (waf.headers.length + 1));
            }
        }

        // 2. Behavioral Fingerprinting (Malicious Payload)
        // Send a known triggering payload to see behavior
        const maliciousUrl = `${url}${url.includes('?') ? '&' : '?'}test=${encodeURIComponent("' OR '1'='1")}`;
        try {
            const blockTest = await axios.get(maliciousUrl, { 
                validateStatus: false, 
                timeout: 5000,
                headers: { 'User-Agent': 'Mozilla/5.0' }
            });
            
            if ([403, 406, 501].includes(blockTest.status)) {
                results.detected = true;
                results.behavior.blockedMalicious = true;
                results.signals.push(`Behavioral Block: HTTP ${blockTest.status}`);
                results.confidence = Math.max(results.confidence, 0.85);
                if (results.name === 'None') results.name = 'Generic WAF / IPS';
            }

            if (blockTest.status === 429) {
                results.behavior.rateLimited = true;
                results.signals.push('Behavioral: Rate Limited (429)');
            }
        } catch (err) {
            // Probably dropped connection which is a WAF signal
            results.detected = true;
            results.behavior.blockedMalicious = true;
            results.signals.push('Behavioral: Connection Dropped');
            results.confidence = Math.max(results.confidence, 0.95);
        }

    } catch (err) {
        console.error('[WAF Scanner Error]:', err.message);
    }

    return results;
}

module.exports = { detectWaf };
