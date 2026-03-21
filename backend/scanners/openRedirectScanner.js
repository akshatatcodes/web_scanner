const axios = require('axios');

const REDIRECT_PARAMS = ["next", "url", "redirect", "returnTo", "target", "r", "goto"];

const scanOpenRedirect = async (baseUrl) => {
  const findings = [];
  const evilUrl = "https://evil.com";

  for (const param of REDIRECT_PARAMS) {
    try {
      const separator = baseUrl.includes('?') ? '&' : '?';
      const url = `${baseUrl}${separator}${param}=${evilUrl}`;

      const res = await axios.get(url, {
        timeout: 5000,
        maxRedirects: 0, // IMPORTANT: Do not follow redirects
        validateStatus: () => true,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scanner' }
      });

      if ([301, 302, 307, 308].includes(res.status)) {
        const location = res.headers.location;
        if (location === evilUrl || location?.startsWith(evilUrl)) {
          findings.push({
            type: "OPEN_REDIRECT",
            severity: "HIGH",
            url,
            parameter: param,
            message: `Confirmed Open Redirect via Location header`,
            evidence: `Location: ${location}`
          });
        }
      }
    } catch (err) {
      // Ignore timeouts and network errors
    }
  }

  return findings;
};

module.exports = { scanOpenRedirect };
