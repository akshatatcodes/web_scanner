const axios = require('axios');
const attackLogger = require('../utils/attackLogger');
const { createProof } = require('./proof/proofStore');

const SSRF_PARAMS = ["url", "dest", "webhook", "proxy", "uri", "path", "continue", "window"];

const scanSSRF = async (baseUrl) => {
  const findings = [];
  const testUrl = "http://169.254.169.254/latest/meta-data/";

  // First get a baseline to compare
  let baselineStatus = 404;
  let baselineLength = 0;
  try {
     attackLogger.log({ type: 'SEND', scanner: 'SSRF', url: baseUrl, payload: 'Baseline request' });
     const baseRes = await axios.get(baseUrl, { 
       timeout: 5000, 
       validateStatus: () => true,
       headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scanner' }
     });
     attackLogger.log({ type: 'RECV', scanner: 'SSRF', url: baseUrl, status: baseRes.status });
     baselineStatus = baseRes.status;
     baselineLength = baseRes.data ? baseRes.data.length : 0;
  } catch (e) {
    attackLogger.log({ type: 'ERROR', scanner: 'SSRF', url: baseUrl, error: e.message });
  }

  for (const param of SSRF_PARAMS) {
    try {
      const separator = baseUrl.includes('?') ? '&' : '?';
      const url = `${baseUrl}${separator}${param}=${testUrl}`;

      const res = await axios.get(url, {
        timeout: 5000,
        validateStatus: () => true,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scanner' }
      });

      const isDifferent = Math.abs((res.data ? res.data.length : 0) - baselineLength) > 100;

      if (res.status === 200 || (res.status !== baselineStatus) || isDifferent) {
        // We only claim potential vector, no confirmed SSRF
        findings.push({
          type: "POTENTIAL_SSRF",
          severity: "INFO",
          url,
          parameter: param,
          message: `SSRF-prone parameter '${param}' accepts URL input without immediate error (Potential Vector)`,
          proof: createProof({
            type: 'POTENTIAL_SSRF',
            url,
            method: 'GET',
            payload: testUrl,
            request: { headers: res.request?.headers || {} },
            response: { status: res.status, headers: res.headers, body: typeof res.data === 'string' ? res.data : JSON.stringify(res.data) },
            responseTime: 0,
            evidence: `Status: ${res.status}, Baseline: ${baselineStatus}, Length diff: ${Math.abs((res.data ? res.data.length : 0) - baselineLength)}`
          })
        });
      }
    } catch (err) {
      if (err.code === 'ECONNABORTED' || (err.message && err.message.includes('timeout'))) {
         findings.push({
          type: "POTENTIAL_SSRF",
          severity: "MEDIUM",
          url: `${baseUrl}?${param}=${testUrl}`,
          parameter: param,
          message: `SSRF-prone parameter '${param}' caused a timeout (Potential Blind SSRF delay)`,
          proof: createProof({
            type: 'POTENTIAL_SSRF',
            url: `${baseUrl}?${param}=${testUrl}`,
            method: 'GET',
            payload: testUrl,
            request: { headers: {} },
            response: { status: 0, headers: {}, body: '' },
            responseTime: 5000,
            evidence: `Request timed out after 5000ms — potential blind SSRF`
          })
        });
      }
    }
  }

  return findings;
};

module.exports = { scanSSRF };
