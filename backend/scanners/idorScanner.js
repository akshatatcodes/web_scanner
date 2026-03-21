const axios = require('axios');
const { createProof } = require('./proof/proofStore');
const attackLogger = require('../utils/attackLogger');
const IGNORE_PARAMS = ["gtm", "fbclid", "utm_source", "utm_medium", "utm_campaign", "cx", "ga"];

const SENSITIVE_KEYS = ["email", "username", "account", "balance", "credit", "role", "payment", "uuid", "token"];

const scanIDOR = async (targetUrls) => {
    const findings = [];
    const seen = new Set();
    const urlsWithParams = targetUrls.filter(u => u.includes('?')).slice(0, 8); // Limit to top 8 candidates

    console.log(`[IDOR Scanner] Probing ${urlsWithParams.length} URLs for IDOR vectors...`);

    for (const urlStr of urlsWithParams) {
        try {
            const urlObj = new URL(urlStr);
            const params = new URLSearchParams(urlObj.search);
            
            let hasIdParam = false;
            for (const key of params.keys()) {
                if (key.toLowerCase().includes('id') || key.toLowerCase().includes('user') || key.toLowerCase().includes('account')) {
                    hasIdParam = true;
                }
            }
            if (!hasIdParam) continue;

            let baselineRes;
            try {
                baselineRes = await axios.get(urlStr, { timeout: 5000, validateStatus: () => true });
            } catch(e) { continue; }

            for (const [key, value] of params.entries()) {
                if (IGNORE_PARAMS.includes(key.toLowerCase())) continue;
                if (!key.toLowerCase().includes('id') && !key.toLowerCase().includes('user') && !key.toLowerCase().includes('account')) continue;
                
                // If it's a numeric ID, iterate it safely
                if (!isNaN(value) && value.trim() !== '') {
                    const findKey = `${key}-idor`;
                    if (seen.has(findKey)) continue;

                    const testUrl = new URL(urlStr);
                    testUrl.searchParams.set(key, parseInt(value) + 1);

                    try {
                        attackLogger.log({ type: 'SEND', scanner: 'IDOR', url: testUrl.toString(), payload: testUrl.searchParams.get(key) });
                        const res = await axios.get(testUrl.toString(), { timeout: 3000, validateStatus: () => true });
                        attackLogger.log({ type: 'RECV', scanner: 'IDOR', url: testUrl.toString(), status: res.status });

                        if (res.status === 200 && baselineStatus !== 200) {
                            attackLogger.log({ type: 'FOUND', scanner: 'IDOR', url: testUrl.toString(), payload: testUrl.searchParams.get(key), severity: 'HIGH', result: `Status change (${baselineStatus}->200)` });
                            seen.add(findKey);
                            findings.push({
                                type: "IDOR",
                                severity: "HIGH",
                                confidence: "Potential",
                                parameter: key,
                                url: testUrl.toString(),
                                message: `Access granted to manipulated numeric ID (Baseline: ${baselineRes.status}, Spoofed: 200)`,
                                proof: createProof({
                                    type: 'IDOR',
                                    url: testUrl.toString(),
                                    method: 'GET',
                                    payload: testUrl.searchParams.get(key),
                                    request: { headers: res.request?.headers || {} },
                                    response: { status: res.status, headers: res.headers, body: typeof res.data === 'string' ? res.data : JSON.stringify(res.data) },
                                    responseTime: 0,
                                    evidence: `Baseline status: ${baselineRes.status}, Spoofed to 200 for param '${key}'`
                                })
                            });
                            continue;
                        }

                        if (res.status === 200 && baselineRes.status === 200) {
                            const isResJson = typeof res.data === 'object' && res.data !== null;
                            const isBaseJson = typeof baselineRes.data === 'object' && baselineRes.data !== null;

                            if (isResJson && isBaseJson) {
                                const resString = JSON.stringify(res.data);
                                const baseString = JSON.stringify(baselineRes.data);
                                
                                const hasSensitive = SENSITIVE_KEYS.some(k => resString.toLowerCase().includes(`"${k}"`) || baseString.toLowerCase().includes(`"${k}"`));
                                
                                if (hasSensitive && resString !== baseString) {
                                    seen.add(findKey);
                                    findings.push({
                                        type: "IDOR",
                                        severity: "HIGH",
                                        confidence: "Potential",
                                        parameter: key,
                                        url: testUrl.toString(),
                                        message: `JSON response differs structurally for manipulated ID (Sensitive keys present)`,
                                        proof: createProof({
                                            type: 'IDOR',
                                            url: testUrl.toString(),
                                            method: 'GET',
                                            payload: testUrl.searchParams.get(key),
                                            request: { headers: res.request?.headers || {} },
                                            response: { status: res.status, headers: res.headers, body: resString },
                                            responseTime: 0,
                                            evidence: `Sensitive keys exposed in JSON response after ID manipulation`
                                        })
                                    });
                                }
                            } else {
                                // Fallback to raw length comparison
                                const resL = typeof res.data === 'string' ? res.data.length : JSON.stringify(res.data).length;
                                const baseL = typeof baselineRes.data === 'string' ? baselineRes.data.length : JSON.stringify(baselineRes.data).length;
                                if (Math.abs(resL - baseL) > 500) {
                                    seen.add(findKey);
                                    findings.push({
                                        type: "IDOR",
                                        severity: "MEDIUM",
                                        confidence: "Potential",
                                        parameter: key,
                                        message: `Significant response length variance upon ID manipulation`
                                    });
                                }
                            }
                        }
                    } catch(e) {}
                }
            }
        } catch(err) {}
    }
    return findings;
};

module.exports = { scanIDOR };
