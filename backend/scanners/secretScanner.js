const axios = require("axios");

const SECRET_PATTERNS = [
  /api[_-]?key\s*[:=]\s*["'][A-Za-z0-9-_]{16,}["']/gi,
  /token\s*[:=]\s*["'][A-Za-z0-9-_]{16,}["']/gi,
  /secret\s*[:=]\s*["'][A-Za-z0-9-_]{16,}["']/gi,
  /password\s*[:=]\s*["'][^"']{6,}["']/gi,
  /AKIA[0-9A-Z]{16}/g // AWS key
];

const scanSecrets = async (scripts) => {
  const findings = [];

  for (const script of scripts) {
    try {
      const res = await axios.get(script);
      const content = res.data;

      for (const pattern of SECRET_PATTERNS) {
        const matches = content.match(pattern);

        if (matches) {
          findings.push({
            type: "SECRET_LEAK",
            severity: "HIGH",
            source: script,
            matches,
            message: "Potential secret or API key leaked in JS"
          });
        }
      }
    } catch (err) {}
  }

  return findings;
};

module.exports = { scanSecrets };
