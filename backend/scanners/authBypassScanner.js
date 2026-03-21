const axios = require('axios');

const BYPASS_HEADERS = [
  { "X-Forwarded-For": "127.0.0.1" },
  { "X-Forwarded-Host": "localhost" },
  { "X-Originating-IP": "127.0.0.1" },
  { "X-Remote-IP": "127.0.0.1" },
  { "X-Rewrite-URL": "/admin" },
  { "X-Original-URL": "/admin" }
];

const BATCH_SIZE = 3;

const FALLBACK_PATHS = [
  '/admin', '/login', '/dashboard', '/config', '/api/v1', '/portal',
  '/setup', '/backup', '/.env', '/users', '/settings'
];

const scanAuthBypass = async (baseUrl, discoveredPaths = []) => {
    // 1. Build intelligent priority list
    const pathsToTest = [...new Set([...discoveredPaths, ...FALLBACK_PATHS])].filter(Boolean).slice(0, 10);
    
    console.log(`[Auth Bypass Scanner] Testing ${pathsToTest.length} paths with ${BYPASS_HEADERS.length} spoofing headers...`);

    const findings = [];
    const urlBase = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;

    for (let i = 0; i < pathsToTest.length; i += BATCH_SIZE) {
        const batch = pathsToTest.slice(i, i + BATCH_SIZE);
        
        await Promise.all(batch.map(async (path) => {
            try {
                // ensure path starts with a slash
                const normalizedPath = path.startsWith('http') ? new URL(path).pathname : (path.startsWith('/') ? path : `/${path}`);
                const targetUrl = `${urlBase}${normalizedPath}`;
                
                // 2. Baseline Request
                const baselineReq = await axios.get(targetUrl, {
                    timeout: 4000,
                    validateStatus: () => true,
                    headers: { 'User-Agent': 'Mozilla/5.0 Scanner Baseline' },
                    maxRedirects: 0
                });

                // Target only explicitly forbidden/unauthorized/redirected pages
                if ([401, 403, 301, 302].includes(baselineReq.status)) {
                    const baselineLength = baselineReq.data ? (typeof baselineReq.data === 'string' ? baselineReq.data.length : JSON.stringify(baselineReq.data).length) : 0;

                    // 3. Spoofed requests (Sequential within the path testing to avoid flooding)
                    for (const headerOpt of BYPASS_HEADERS) {
                        try {
                            const headers = { 'User-Agent': 'Mozilla/5.0 Scanner Spoof', ...headerOpt };
                            if (headerOpt["X-Rewrite-URL"] || headerOpt["X-Original-URL"]) headers[Object.keys(headerOpt)[0]] = normalizedPath;

                            const spoofReq = await axios.get(targetUrl, {
                                timeout: 4000,
                                validateStatus: () => true,
                                headers,
                                maxRedirects: 0
                            });

                            if (spoofReq.status === 200) {
                                const spoofLength = spoofReq.data ? (typeof spoofReq.data === 'string' ? spoofReq.data.length : JSON.stringify(spoofReq.data).length) : 0;
                                const bodyText = spoofReq.data && typeof spoofReq.data === 'string' ? spoofReq.data.toLowerCase() : '';

                                if (Math.abs(spoofLength - baselineLength) > 100 || ['admin', 'dashboard', 'welcome', 'logout', 'settings'].some(k => bodyText.includes(k))) {
                                    findings.push({
                                        type: "AUTH_BYPASS",
                                        severity: "HIGH",
                                        url: targetUrl,
                                        message: `Authentication Bypass successful`,
                                        evidence: `Header Injection: ${JSON.stringify(headers).replace(/[{}]/g, '')}`
                                    });
                                    break; 
                                }
                            }
                        } catch (e) {}
                    }
                }
            } catch (err) {}
        }));
    }
    return findings;
};

module.exports = { scanAuthBypass };
