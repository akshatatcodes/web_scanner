const axios = require('axios');
const { safeRequest } = require('./utils');

/**
 * Fetches historical URLs from the Wayback Machine (CDX API)
 * Extracts parameters, unique endpoints, and sensitive extensions.
 */
const extractWaybackData = async (domain) => {
    const url = `http://web.archive.org/cdx/search/cdx?url=*.${domain}/*&collapse=urlkey&output=json&fl=original&limit=300`;
    
    const res = await safeRequest(() => axios.get(url, { timeout: 15000 }), 2);
    if (!res || !res.data || !Array.isArray(res.data) || res.data.length <= 1) {
        return { parameters: [], endpoints: 0, rawUrls: [] };
    }

    const allUrls = res.data.slice(1).map(row => row[0]); // Skip header row
    
    const uniqueParams = new Set();
    const uniqueEndpoints = new Set();
    
    for (const archiveUrl of allUrls) {
        try {
            const parsed = new URL(archiveUrl);
            uniqueEndpoints.add(parsed.pathname);
            
            for (const key of parsed.searchParams.keys()) {
                uniqueParams.add(key.toLowerCase());
            }
        } catch(e) {}
    }

    // Convert Sets to Arrays
    return {
        rawUrls: allUrls,
        endpoints: uniqueEndpoints.size,
        parameters: Array.from(uniqueParams)
    };
};

module.exports = { extractWaybackData };
