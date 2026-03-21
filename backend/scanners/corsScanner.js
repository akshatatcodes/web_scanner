const axios = require('axios');

const scanCORS = async (url) => {
  const findings = [];
  try {
    const evilOrigin = 'https://evil.com';
    const res = await axios.get(url, {
      timeout: 5000,
      headers: {
        'Origin': evilOrigin,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scanner'
      },
      validateStatus: () => true
    });

    const acao = res.headers['access-control-allow-origin'];
    const acac = res.headers['access-control-allow-credentials'];

    if (acao) {
      if (acao === evilOrigin && acac === 'true') {
        findings.push({
          type: "CORS_MISCONFIGURATION",
          severity: "HIGH",
          message: "Origin reflection with credentials enabled (Highly Exploitable)",
          evidence: `Access-Control-Allow-Origin: ${evilOrigin}\nAccess-Control-Allow-Credentials: true`
        });
      } else if (acao === '*' && acac === 'true') {
        findings.push({
          type: "CORS_MISCONFIGURATION",
          severity: "HIGH",
          message: "Wildcard origin with credentials enabled (Invalid spec but dangerous if custom clients parse it)",
          evidence: "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true"
        });
      } else if (acao === evilOrigin) {
        findings.push({
          type: "CORS_MISCONFIGURATION",
          severity: "MEDIUM",
          message: "Origin reflection without credentials (Potentially Exploitable)",
          evidence: `Access-Control-Allow-Origin: ${evilOrigin}`
        });
      } else if (acao === '*') {
           findings.push({
            type: "CORS_MISCONFIGURATION",
            severity: "LOW",
            message: "Wildcard origin without credentials (Information Disclosure)",
            evidence: `Access-Control-Allow-Origin: *`
          });
      }
    }
  } catch (e) {
    // Ignore errors
  }
  return findings;
};

module.exports = { scanCORS };
