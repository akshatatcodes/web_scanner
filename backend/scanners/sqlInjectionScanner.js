const axios = require('axios');
const { generatePayloads } = require('../utils/payloadEngine');
const { createProof } = require('./proof/proofStore');
const attackLogger = require('../utils/attackLogger');
const SAFE_MODE = true;

const DB_ERRORS = [
    "SQL syntax", "mysql_fetch_array", "ORA-", "PostgreSQL",
    "SQLServer", "SQLite/JDBCDriver", "System.Data.SQLClient"
];

const scanSQLi = async (targetUrls, scanContext = {}) => {
    const findings = [];
    const seen = new Set();
    const urlsWithParams = targetUrls.filter(u => u.includes('?')).slice(0, 5); 
    
    console.log(`[SQLi Scanner] Probing ${urlsWithParams.length} URLs for injection...`);

    for (const urlStr of urlsWithParams) {
        try {
            const urlObj = new URL(urlStr);
            const params = new URLSearchParams(urlObj.search);
            if (params.toString() === '') continue;

            // 1. Baseline
            let baselineRes;
            let baselineBody = "";
            try {
                baselineRes = await axios.get(urlStr, { timeout: 5000, validateStatus: () => true });
                baselineBody = typeof baselineRes.data === 'string' ? baselineRes.data : JSON.stringify(baselineRes.data);
            } catch (e) { continue; }

            for (const [key, value] of params.entries()) {
                // A. Adaptive Error-based Payloads
                const testPayloads = generatePayloads('sqli', scanContext);

                let dbErrorFound = false;
                for (const payload of testPayloads) {
                    const findKey = `${key}-error-${payload}`;
                    if (seen.has(findKey)) continue;

                    const testUrl = new URL(urlStr);
                    testUrl.searchParams.set(key, value + payload);

                    try {
                        const res = await axios.get(testUrl.toString(), { timeout: 5000, validateStatus: () => true });
                        const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
                        attackLogger.log({ type: 'SEND', scanner: 'SQLi', url: testUrl.toString(), payload });
                        attackLogger.log({ type: 'RECV', scanner: 'SQLi', url: testUrl.toString(), status: res.status });
                        
                        // Error MUST not be in baseline
                        const foundError = DB_ERRORS.find(err => body.includes(err) && !baselineBody.includes(err));
                        if (foundError) {
                            seen.add(findKey);
                            attackLogger.log({ type: 'FOUND', scanner: 'SQLi', url: testUrl.toString(), payload, severity: 'CRITICAL', result: `DB error: ${foundError}` });
                            findings.push({
                                type: "SQL_INJECTION",
                                severity: "CRITICAL",
                                confidence: "Confirmed",
                                parameter: key,
                                url: testUrl.toString(),
                                message: `Database error exposed: ${foundError}`,
                                proof: createProof({
                                    type: 'SQL_INJECTION',
                                    url: testUrl.toString(),
                                    method: 'GET',
                                    payload,
                                    request: { headers: res.request?.headers || {} },
                                    response: { status: res.status, headers: res.headers, body: body },
                                    responseTime: 0,
                                    evidence: `DB error string in response: "${foundError}"`
                                })
                            });
                            dbErrorFound = true;
                            break; 
                        }
                    } catch(e){}
                }

                if (dbErrorFound) continue;

                // B. Boolean-based Differential Analysis
                const trueUrl = new URL(urlStr);
                trueUrl.searchParams.set(key, `${value} AND 1=1`);
                const falseUrl = new URL(urlStr);
                falseUrl.searchParams.set(key, `${value} AND 1=2`);

                try {
                    const [resTrue, resFalse] = await Promise.all([
                        axios.get(trueUrl.toString(), { timeout: 5000, validateStatus: () => true }),
                        axios.get(falseUrl.toString(), { timeout: 5000, validateStatus: () => true })
                    ]);

                    const baselineL = typeof baselineRes.data === 'string' ? baselineRes.data.length : JSON.stringify(baselineRes.data).length;
                    const trueL = typeof resTrue.data === 'string' ? resTrue.data.length : JSON.stringify(resTrue.data).length;
                    const falseL = typeof resFalse.data === 'string' ? resFalse.data.length : JSON.stringify(resFalse.data).length;

                    if (resTrue.status === baselineRes.status && resFalse.status !== baselineRes.status) {
                        findings.push({
                            type: "SQL_INJECTION",
                            severity: "HIGH",
                            confidence: "High Probability",
                            parameter: key,
                            url: trueUrl.toString(),
                            message: `Boolean-based SQLi detected (Status differential)`,
                            proof: createProof({
                                type: 'SQL_INJECTION',
                                url: trueUrl.toString(),
                                method: 'GET',
                                payload: `${value} AND 1=1 / AND 1=2`,
                                request: { headers: resTrue.request?.headers || {} },
                                response: { status: resTrue.status, headers: resTrue.headers, body: typeof resTrue.data === 'string' ? resTrue.data : JSON.stringify(resTrue.data) },
                                responseTime: 0,
                                evidence: `Status diff: TRUE=${resTrue.status}, FALSE=${resFalse.status}, Baseline=${baselineRes.status}`
                            })
                        });
                    } else if (Math.abs(trueL - baselineL) < 50 && Math.abs(trueL - falseL) > 100) {
                        findings.push({
                            type: "SQL_INJECTION",
                            severity: "HIGH",
                            confidence: "Potential",
                            parameter: key,
                            url: trueUrl.toString(),
                            message: `Boolean-based SQLi detected (Length diff: True=${trueL}, False=${falseL})`,
                            proof: createProof({
                                type: 'SQL_INJECTION',
                                url: trueUrl.toString(),
                                method: 'GET',
                                payload: `${value} AND 1=1 / AND 1=2`,
                                request: { headers: resTrue.request?.headers || {} },
                                response: { status: resTrue.status, headers: resTrue.headers, body: typeof resTrue.data === 'string' ? resTrue.data : JSON.stringify(resTrue.data) },
                                responseTime: 0,
                                evidence: `Length diff: True=${trueL}, False=${falseL}, Baseline=${baselineL}`
                            })
                        });
                    }
                } catch(e) {}
            }
        } catch(err) {}
    }
    return findings;
};

module.exports = { scanSQLi };
