const axios = require("axios");

const SECRET_PATTERNS = [
  // Generic
  /(?:apiKey|api_key|api-key|secret|token|auth|password|passwd|pwd|access_token|secret_key|secret_token|private_key|key|apikey|authorization|bearer|cred|credential)[\s:=]+['"`]([A-Za-z0-9_\-\.\~]{16,})['"`]/gi,
  
  // Cloud & Services
  /AIza[0-9A-Za-z\-_]{35}/g, // Google API Key
  /AKIA[0-9A-Z]{16}/g,       // AWS Access Key
  /ASCA[0-9A-Z]{16}/g,       // AWS Key
  /SK[0-9a-fA-F]{32}/g,      // Stripe Secret Key
  /sq0atp-[0-9A-Za-z\-_]{22}/g, // Square Access Token
  /sq0csp-[0-9A-Za-z\-_]{43}/g, // Square OAuth Secret
  /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g, // PayPal Access Token
  /xoxp-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}/g, // Slack User Token
  /xoxb-[0-9]{12}-[0-9]{12}-[a-z0-9]{24}/g, // Slack Bot Token
  /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/g, // SendGrid API Key
  /key-[0-9a-zA-Z]{32}/g, // Mailgun API Key
  /AC[a-f0-9]{32}/g, // Twilio Account SID
  /ghp_[a-zA-Z0-9]{36}/g, // GitHub Personal Access Token
  
  // Infrastructure
  /mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9.-]+\/[a-zA-Z0-9_]+/gi, // MongoDB URI
  /postgres(?:ql)?:\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9.-]+:[0-9]+\/[a-zA-Z0-9_]+/gi, // Postgres URI
  /redis:\/\/[a-zA-Z0-9_]*:[a-zA-Z0-9_]+@[a-zA-Z0-9.-]+:[0-9]+/gi, // Redis URI
  
  // Crypto/Private Keys
  /-----BEGIN (?:RSA|OPENSSH|PGP|PRIVATE) KEY-----[\s\S]+?-----END (?:RSA|OPENSSH|PGP|PRIVATE) KEY-----/g,
  
  // JWT (Loose pattern for discovery)
  /ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g
];

const scanSecrets = async (scriptsOrContent) => {
  const findings = [];
  const items = Array.isArray(scriptsOrContent) ? scriptsOrContent : [scriptsOrContent];

  for (const item of items) {
    let content = "";
    let source = "Internal/Main Page";

    try {
      if (typeof item === 'string' && (item.startsWith('http') || item.startsWith('file'))) {
        source = item;
        const res = await axios.get(item, { timeout: 8000, validateStatus: null });
        content = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
      } else if (typeof item === 'string') {
        content = item;
      } else if (item && item.content) {
        content = item.content;
        source = item.src || "inline_script";
      }

      if (!content) continue;

      for (const pattern of SECRET_PATTERNS) {
        const matches = content.match(pattern);

        if (matches) {
          // Remove duplicates and handle the case where matches might be a large array
          const uniqueMatches = [...new Set(matches)].slice(0, 10); 
          findings.push({
            type: "SECRET_LEAK",
            severity: "CRITICAL",
            source: source,
            matches: uniqueMatches,
            message: `Sensitive information or API keys leaked in ${source === 'Internal/Main Page' ? 'page content' : 'JS source'}.`
          });
        }
      }
      
      // Basic Entropy Detection for suspicious high-randomness strings
      const words = content.split(/\s+|['"`,;=()]/);
      for (const word of words) {
          if (word.length > 32 && word.length < 64 && /^[A-Za-z0-9\-_]+$/.test(word)) {
              // Simple check for high entropy (approximate)
              const charCount = new Set(word).size;
              if (charCount > 20) {
                  findings.push({
                      type: "SENSITIVE_DATA",
                      severity: "MEDIUM",
                      source: source,
                      matches: [word.substring(0, 8) + "..."],
                      message: "High-entropy string detected; potential obfuscated secret."
                  });
              }
          }
      }

    } catch (err) {}
  }

  return findings;
};

module.exports = { scanSecrets };
