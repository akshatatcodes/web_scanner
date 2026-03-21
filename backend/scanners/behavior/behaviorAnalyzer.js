const { getBaseline, detectAnomaly } = require('./anomalyDetector');
const { mutate } = require('./payloadMutator');
const { safeRequest, pLimit } = require('../../recon/utils');
const axios = require('axios');

const PAYLOAD_DICTIONARY = {
    'Blind SQL Injection': [
        "SLEEP(3)",
        "' OR SLEEP(3)--"
    ],
    'Command Injection': [
        "; sleep 3",
        "$(sleep 3)"
    ],
    'LFI': [
        "../../../../../../../../etc/passwd"
    ],
    'Auth Bypass': [
        "' OR 1=1--"
    ]
};

const injectPayload = async (baseUrl, payload) => {
    try {
        const url = new URL(baseUrl);
        const testUrl = new URL(baseUrl);
        
        const params = Array.from(url.searchParams.keys());
        if (params.length > 0) {
            testUrl.searchParams.set(params[0], payload);
        } else {
            testUrl.searchParams.append('testParam', payload);
        }

        const start = Date.now();
        const res = await safeRequest(() => axios.get(testUrl.href, { timeout: 5000, validateStatus: () => true }), 1);
        const time = Date.now() - start;

        if (!res) return null;

        return {
            status: res.status,
            length: res.data ? JSON.stringify(res.data).length : 0,
            time,
            body: res.data && typeof res.data === 'string' ? res.data : ''
        };
    } catch(e) { return null; }
};

const confirmAnomaly = async (url, payload, requiredCount = 2) => {
    let successCount = 0;
    for (let i = 0; i < requiredCount; i++) {
        const bl = await getBaseline(url);
        const t = await injectPayload(url, payload);
        if (bl && t) {
            const anom = detectAnomaly(bl, t);
            if (anom && anom.timeAnomaly) successCount++;
        }
    }
    return successCount === requiredCount;
};

const runBehaviorAnalysis = async (endpoints) => {
    console.log(`[Behavior Analyzer] Starting deep analysis on ${endpoints.length} endpoints...`);
    const limit = pLimit(3); // Lower concurrency to avoid self-DOS
    const findings = [];
    let totalPayloadsSent = 0;

    const analyzeEndpoint = async (urlObj) => {
        const url = typeof urlObj === 'string' ? urlObj : urlObj.url;
        console.log(`[Behavior Analyzer] Initializing baseline for: ${url}`);
        
        const baseline = await getBaseline(url);
        if (!baseline) {
            console.log(`[Behavior Analyzer] Failed to get baseline for: ${url}`);
            return;
        }

        let payloadCount = 0;
        const maxTimePerEndpoint = 15000; // Max 15 seconds per endpoint
        const startTime = Date.now();

        for (const [vulnType, payloads] of Object.entries(PAYLOAD_DICTIONARY)) {
            if (Date.now() - startTime > maxTimePerEndpoint) break;

            for (const basePayload of payloads) {
                if (Date.now() - startTime > maxTimePerEndpoint) break;

                const mutations = mutate(basePayload).slice(0, 2); // Limit to top 2 mutations
                
                for (const payload of mutations) {
                    if (Date.now() - startTime > maxTimePerEndpoint) break;
                    
                    payloadCount++;
                    totalPayloadsSent++;
                    const testRes = await injectPayload(url, payload);
                    if (!testRes) continue;

                    const anomaly = detectAnomaly(baseline, testRes);
                    if (!anomaly) continue;

                    // 1. Time Based Injection (SQLi / Cmdi)
                    if (anomaly.timeAnomaly && payload.toLowerCase().includes('sleep')) {
                        console.log(`[Behavior Analyzer] Alert! Time anomaly detected at ${url} with '${payload}'. Confirming...`);
                        const confirmed = await confirmAnomaly(url, payload, 1); // 1 extra confirmation to save time
                        if (confirmed) {
                            console.log(`[Behavior Analyzer] CONFIRMED: ${vulnType} at ${url}`);
                            findings.push({
                                endpoint: url,
                                vulnerability: vulnType,
                                confidence: "HIGH",
                                evidence: { baselineTime: baseline.time, payloadTime: testRes.time, payload }
                            });
                            return;
                        }
                    }

                    // 2. LFI / Command Injection Static Body Validation
                    if (vulnType === 'LFI' || vulnType === 'Command Injection') {
                        if (testRes.body.includes('root:x:0:0') || testRes.body.includes('[extensions]')) {
                            console.log(`[Behavior Analyzer] CONFIRMED: ${vulnType} at ${url}`);
                            findings.push({
                                endpoint: url,
                                vulnerability: vulnType,
                                confidence: "CRITICAL",
                                evidence: { payload, snippet: "System files dumped to output." }
                            });
                            return;
                        }
                    }

                    // 3. Logic Flaws / Auth Bypass
                    if (vulnType === 'Auth Bypass' && anomaly.statusChange) {
                        if (baseline.status === 401 && testRes.status === 200) {
                            console.log(`[Behavior Analyzer] CONFIRMED: Auth Bypass at ${url}`);
                            findings.push({
                                endpoint: url,
                                vulnerability: vulnType,
                                confidence: "HIGH",
                                evidence: { baselineStatus: baseline.status, payloadStatus: testRes.status, payload }
                            });
                            return;
                        }
                    }
                }
            }
        }
        console.log(`[Behavior Analyzer] Finished ${url} (${payloadCount} payloads sent in ${Date.now() - startTime}ms)`);
    };

    const targetEndpoints = Array.isArray(endpoints) ? endpoints.slice(0, 5) : [];
    console.log(`[Behavior Analyzer] Processing top ${targetEndpoints.length} endpoints...`);
    
    await Promise.all(targetEndpoints.map(e => limit(() => analyzeEndpoint(e))));

    console.log(`[Behavior Analyzer] Found ${findings.length} confirmed behavioral anomalies out of ${totalPayloadsSent} evaluated payloads.`);
    return {
        endpointsProfiled: targetEndpoints.length,
        payloadsSent: totalPayloadsSent,
        anomalies: findings
    };
};

module.exports = { runBehaviorAnalysis };
