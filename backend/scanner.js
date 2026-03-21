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
        console.error('Scanner Proxy Error:', err.message);
        throw new Error(`Failed to complete SUPER scan: ${err.message}`);
    }
}

module.exports = { scanUrl };
