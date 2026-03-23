const axios = require('axios');
const { generatePayloads } = require('../utils/payloadEngine');
const { createProof } = require('./proof/proofStore');
const attackLogger = require('../utils/attackLogger');
const SAFE_MODE = true;

const IGNORE_PARAMS = ["gtm", "fbclid", "utm_source", "utm_medium", "utm_campaign", "cx", "ga"];

const CMD_REGEX_PATTERNS = [
    /uid=\d+\(.+?\)/,
    /gid=\d+\(.+?\)/,
    /root:x:0:0/,
    /bin\/(ba)?sh/,
    /\[font\]/
];

const scanCommandInjection = async (targetUrls, scanContext = {}) => {
    const findings = [];
    const seen = new Set();
    const urlsWithParams = targetUrls.filter(u => u.includes('?')).slice(0, 5); // Limit to top 5 candidates

    console.log(`[Cmd Injection Scanner] Probing ${urlsWithParams.length} URLs for OS injection...`);

    const payloads = generatePayloads('cmd', scanContext);

    for (const urlStr of urlsWithParams) {
        try {
            const urlObj = new URL(urlStr);
            const params = new URLSearchParams(urlObj.search);
            
            // Baseline timing and content
            let baselineDuration = 0;
            let baselineBody = "";
            try {
                const s = Date.now();
                const bRes = await axios.get(urlStr, { timeout: 5000, validateStatus: () => true });
                baselineDuration = Date.now() - s;
                baselineBody = typeof bRes.data === 'string' ? bRes.data : JSON.stringify(bRes.data);
            } catch (e) { continue; }

            for (const [key, value] of params.entries()) {
                if (IGNORE_PARAMS.includes(key.toLowerCase())) continue;

                for (const payload of payloads) {
                    const findKey = `${key}-${urlObj.pathname}-${payload.includes('sleep') ? 'time' : 'output'}`;
                    if (seen.has(findKey)) continue;

                    const testUrl = new URL(urlStr);
                    testUrl.searchParams.set(key, value + payload);

                    const start = Date.now();
                    try {
                        const res = await axios.get(testUrl.toString(), { timeout: 6000, validateStatus: () => true });
                        const duration = Date.now() - start;
                        const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);

                        attackLogger.log({ type: 'SEND', scanner: 'CmdInj', url: testUrl.toString(), payload });
                        attackLogger.log({ type: 'RECV', scanner: 'CmdInj', url: testUrl.toString(), status: res.status, result: `${duration}ms` });

                        // 1. Time-based Confirmation (Confidence: HIGH)
                        if (payload.includes('sleep 2') && duration > (baselineDuration + 1800)) {
                            seen.add(findKey);
                            attackLogger.log({ type: 'FOUND', scanner: 'CmdInj', url: testUrl.toString(), payload, severity: 'CRITICAL', result: `Time-based RCE: ${duration}ms delay` });
                            findings.push({
                                type: "COMMAND_INJECTION",
                                severity: "CRITICAL",
                                confidence: "Confirmed",
                                parameter: key,
                                url: testUrl.toString(),
                                message: `Time-based Command Injection (Delayed by ${duration}ms, Baseline: ${baselineDuration}ms)`,
                                proof: createProof({
                                    type: 'COMMAND_INJECTION',
                                    url: testUrl.toString(),
                                    method: 'GET',
                                    payload,
                                    request: { headers: res.request?.headers || {} },
                                    response: { status: res.status, headers: res.headers, body: body },
                                    responseTime: duration,
                                    evidence: `Time delay of ${duration}ms vs baseline ${baselineDuration}ms`
                                })
                            });
                        }

                        // 2. Output-based Regex Matching (Confidence: MEDIUM/HIGH if diff found)
                        const matchedPattern = CMD_REGEX_PATTERNS.find(p => p.test(body));
                        if (matchedPattern && !matchedPattern.test(baselineBody)) {
                            seen.add(findKey);
                            attackLogger.log({ type: 'FOUND', scanner: 'CmdInj', url: testUrl.toString(), payload, severity: 'CRITICAL', result: `Output match: ${matchedPattern}` });
                            findings.push({
                                type: "COMMAND_INJECTION",
                                severity: "CRITICAL",
                                confidence: "Confirmed",
                                parameter: key,
                                url: testUrl.toString(),
                                message: `OS Command Execution output detected (Pattern: ${matchedPattern})`,
                                proof: createProof({
                                    type: 'COMMAND_INJECTION',
                                    url: testUrl.toString(),
                                    method: 'GET',
                                    payload,
                                    request: { headers: res.request?.headers || {} },
                                    response: { status: res.status, headers: res.headers, body: body },
                                    responseTime: duration,
                                    evidence: `Pattern matched: ${matchedPattern}`
                                })
                            });
                        }
                    } catch(e) {}
                }
            }
        } catch(err) {}
    }
    return findings;
};

module.exports = { scanCommandInjection };
