const dns = require('dns').promises;
const axios = require('axios');
const { safeRequest, pLimit } = require('./utils');

/**
 * Attempts to bypass CDN by looking at subdomains that might bypass the WAF/CDN
 * and point directly to the origin server.
 */
const checkCdnBypass = async (domain, mainIp, subdomains, isCloud) => {
    if (!isCloud) return { bypassed: false, message: "Target is not behind a known CDN." };

    const limit = pLimit(15);
    const uniqueIps = new Set();
    const subStrToIp = {};

    // 1. Resolve all subdomains to find alternative IPs
    const resolutionPromises = subdomains.map(sub => limit(async () => {
        try {
            const ips = await dns.resolve4(sub);
            if (ips && ips.length > 0) {
                const ip = ips[0];
                if (ip !== mainIp) {
                    uniqueIps.add(ip);
                    subStrToIp[ip] = sub;
                }
            }
        } catch (e) {}
    }));

    await Promise.all(resolutionPromises);

    const candidates = Array.from(uniqueIps);
    if (candidates.length === 0) {
        return { bypassed: false, message: "No origin IP candidates found via subdomains." };
    }

    // 2. Test candidates via Host Header injection
    let originExposed = false;
    let originIp = null;
    let bypassSource = null;

    const testPromises = candidates.map(ip => limit(async () => {
        if (originExposed) return; // Stop if already found
        
        try {
            // Direct request to the IP but claiming to be the main domain
            const url = `http://${ip}`;
            const res = await safeRequest(() => axios.get(url, {
                headers: { 'Host': domain, 'User-Agent': 'Mozilla/5.0' },
                timeout: 5000,
                validateStatus: null
            }), 1);
            
            if (res && res.status >= 200 && res.status < 500) {
                // If it responds properly instead of throwing a generic CDN error, we likely hit origin.
                // We'd ideally compare DOM similarity, but status code is a good heuristic for now.
                originExposed = true;
                originIp = ip;
                bypassSource = subStrToIp[ip];
            }
        } catch (e) {}
    }));

    await Promise.all(testPromises);

    if (originExposed) {
        return {
            bypassed: true,
            originIp,
            leakedVia: bypassSource,
            message: `CDN Bypassed! Origin IP ${originIp} exposed via ${bypassSource}`
        };
    }

    return { bypassed: false, message: "Failed to bypass CDN footprint using subdomain IPs." };
};

module.exports = { checkCdnBypass };
