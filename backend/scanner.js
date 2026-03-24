const engine = require('./engine');

/**
 * Entry point for scanning a URL.
 * Now delegates to the modular SUPER engine.
 */
async function scanUrl(url, options = {}) {
    try {
        const results = await engine.run(url, options);
        return results;
    } catch (err) {
        console.error('Scanner Proxy Error:', err.message || err);
        let errorMsg = err.message;
        if (err.name === 'AggregateError' && err.errors && err.errors.length > 0) {
            errorMsg = err.errors.map(e => e.message || e.code).join(', ');
        }
        throw new Error(`Failed to complete Vulnexa scan: ${errorMsg || 'Unknown error occurred'}`);
    }
}

module.exports = { scanUrl };
