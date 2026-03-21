const crypto = require('crypto');

const SENSITIVE_HEADERS = ['authorization', 'cookie', 'x-api-key', 'x-auth-token', 'set-cookie'];

/**
 * Sanitize headers to remove sensitive values before storing
 */
function sanitizeHeaders(headers = {}) {
    const sanitized = {};
    for (const [key, value] of Object.entries(headers)) {
        if (SENSITIVE_HEADERS.includes(key.toLowerCase())) {
            sanitized[key] = '[REDACTED]';
        } else {
            sanitized[key] = value;
        }
    }
    return sanitized;
}

/**
 * Create a standardized proof object for a detected vulnerability.
 *
 * @param {object} opts
 * @param {string} opts.type         - Vulnerability type (e.g. "COMMAND_INJECTION")
 * @param {string} opts.url          - The exact URL tested (with payload)
 * @param {string} [opts.method]     - HTTP method used (default: GET)
 * @param {string} [opts.payload]    - The attack payload injected
 * @param {object} [opts.request]    - Request details: { headers, body }
 * @param {object} [opts.response]   - Response details: { status, headers, body }
 * @param {number} [opts.responseTime] - Response time in ms
 * @param {string} [opts.evidence]   - Any additional evidence string
 */
function createProof({ type, url, method = 'GET', payload = '', request = {}, response = {}, responseTime = 0, evidence = '' }) {
    // Deduplication hash based on payload + url
    const hash = crypto.createHash('md5').update(payload + url).digest('hex');

    const responseBody = typeof response.body === 'string'
        ? response.body
        : (response.body !== undefined ? JSON.stringify(response.body) : '');

    return {
        id: hash,
        vulnerability: type,
        endpoint: url,
        method: method.toUpperCase(),
        payload,

        request: {
            url,
            method: method.toUpperCase(),
            headers: sanitizeHeaders(request.headers || {}),
            body: request.body || null,
        },

        response: {
            status: response.status || 0,
            headers: sanitizeHeaders(response.headers || {}),
            body: responseBody.slice(0, 2000), // Cap at 2KB to prevent bloat
        },

        meta: {
            responseTime,
            evidence,
            timestamp: new Date().toISOString(),
        },
    };
}

module.exports = { createProof };
