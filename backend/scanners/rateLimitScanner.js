const axios = require('axios');

const scanRateLimit = async (url) => {
    const findings = [];
    const MAX_REQUESTS = 25;
    const DELAY_MS = 30; // 30ms safety delay

    let has429 = false;
    let hasRetryAfter = false;
    let baselineData = null;
    let baselineStatus = 200;
    const responseTimes = [];

    // Intelligent Severity Classification
    const isLogin = url.toLowerCase().includes('login') || url.toLowerCase().includes('signin') || url.toLowerCase().includes('auth');
    const isApi = url.toLowerCase().includes('api');
    
    let severity = 'LOW';
    if (isLogin) severity = 'HIGH';
    else if (isApi) severity = 'MEDIUM';

    try {
        const startBase = Date.now();
        const baseRes = await axios.get(url, { 
            timeout: 5000, 
            validateStatus: () => true, 
            headers: { 'User-Agent': 'Mozilla/5.0 Scanner-RateLimit-Base' } 
        });
        baselineStatus = baseRes.status;
        baselineData = baseRes.data;
        responseTimes.push(Date.now() - startBase);
    } catch (e) {
        return findings; // Exit cleanly if baseline fails
    }

    const testRequests = [];
    for (let i = 0; i < MAX_REQUESTS; i++) {
        testRequests.push(async () => {
            const start = Date.now();
            try {
                const res = await axios.get(url, {
                    timeout: 5000,
                    validateStatus: () => true,
                    headers: { 'User-Agent': `Mozilla/5.0 Scanner Burst-${i}` }
                });
                
                responseTimes.push(Date.now() - start);

                // Check standard headers/codes
                if (res.status === 429 || res.status === 503) {
                    has429 = true;
                }
                if (res.headers && res.headers['retry-after']) {
                    hasRetryAfter = true;
                }
                
                // Advanced: Check for body changes indicating a block page (Captcha/WAF)
                if (res.status === baselineStatus && baselineData) {
                    const diff = Math.abs((res.data ? res.data.length : 0) - (baselineData.length || 0));
                    if (diff > 500 && typeof res.data === 'string') {
                        const dl = res.data.toLowerCase();
                        if (dl.includes('captcha') || dl.includes('blocked') || dl.includes('access denied') || dl.includes('cloudflare')) {
                            has429 = true; // Soft block
                        }
                    }
                }

            } catch (err) {
                // Connection drops can be a sign of throttling via TCP close
                responseTimes.push(Date.now() - start);
                if (err.code === 'ECONNRESET') has429 = true; 
            }
        });
    }

    // 2. Safe execution burst mapping
    for (const req of testRequests) {
        req(); // execute async
        await new Promise(r => setTimeout(r, DELAY_MS)); // spacing delay to prevent server crashes
    }

    // Wait for the long tail
    await new Promise(r => setTimeout(r, 2000));

    // 3. Smart Conclusion
    if (has429 || hasRetryAfter) {
        // Target is protected
    } else {
        const avgFirst3 = responseTimes.slice(0, 3).reduce((a, b) => a + b, 0) / 3;
        const avgLast3 = responseTimes.slice(-3).reduce((a, b) => a + b, 0) / (Math.max(1, responseTimes.slice(-3).length));

        if (avgLast3 > avgFirst3 * 3 && avgLast3 > 1000) {
            findings.push({
                type: "SOFT_RATE_LIMIT",
                severity: "INFO",
                url,
                message: `Soft Rate Limiting present (Latency throttled on consecutive requests)`
            });
        } else {
            findings.push({
                type: "MISSING_RATE_LIMIT",
                severity: severity,
                url,
                message: `Missing Rate Limit Protection on ${severity === 'HIGH' ? 'Authentication' : severity === 'MEDIUM' ? 'API' : 'General'} Endpoint`
            });
        }
    }

    return findings;
};

module.exports = { scanRateLimit };
