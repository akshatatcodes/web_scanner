const axios = require('axios');

/**
 * Security Header Scanner Module
 */
async function scan(url) {
    try {
        const res = await axios.get(url, { timeout: 10000, validateStatus: null });
        const headers = res.headers;

        return {
            hsts: headers['strict-transport-security'] || 'Not Enabled',
            csp: headers['content-security-policy'] || 'Not Enabled',
            xFrame: headers['x-frame-options'] || 'Not Enabled',
            xss: headers['x-xss-protection'] || 'Not Enabled',
            contentType: headers['x-content-type-options'] || 'Not Enabled',
            referrer: headers['referrer-policy'] || 'Not Enabled',
            server: headers['server'] || 'Hidden'
        };
    } catch (error) {
        console.error('Header Scanner Error:', error.message);
        return { error: 'Failed to fetch headers' };
    }
}

module.exports = { scan };
