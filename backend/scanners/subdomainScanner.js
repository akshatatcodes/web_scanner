const axios = require('axios');
const attackLogger = require('../utils/attackLogger');

/**
 * Passive Subdomain Enumeration Module
 * Uses Certificate Transparency (CRT.SH) to find subdomains.
 */
async function scan(domain) {
    try {
        console.log(`[Subdomain Scanner] Enumerating subdomains for: ${domain}`);
        
        const response = await axios.get(`https://crt.sh/?q=%25.${domain}&output=json`, {
            timeout: 30000 // 30 second timeout
        });

        const data = response.data;
        if (!Array.isArray(data)) return [];

        const subdomains = new Set();
        data.forEach(entry => {
            const names = entry.name_value.split('\n');
            names.forEach(name => {
                const cleaned = name.trim().toLowerCase();
                // Filter wildcard and only keep matching domain
                if (cleaned.includes(domain) && !cleaned.includes('*')) {
                    subdomains.add(cleaned);
                }
            });
        });

        const found = Array.from(subdomains);
        attackLogger.log({ type: 'INFO', scanner: 'Recon', url: domain, result: `Found ${found.length} subdomains: ${found.join(', ')}` });
        const results = found.sort();
        console.log(`[Subdomain Scanner] Found ${results.length} subdomains.`);
        return results;

    } catch (error) {
        console.error('[Subdomain Scanner] Error:', error.message);
        return [];
    }
}

module.exports = { scan };
