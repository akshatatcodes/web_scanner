const axios = require("axios");

const SENSITIVE_PATTERNS = [
    {
        type: "EMAIL_ADDRESS",
        pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi,
        severity: "INFO",
        message: "Email address discovered in source code."
    },
    {
        type: "INTERNAL_IP",
        pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
        severity: "MEDIUM",
        message: "Internal IP address (RFC1918) leaked in source code."
    },
    {
        type: "CLOUD_STORAGE",
        pattern: /(?:[a-z0-9.-]+\.s3\.amazonaws\.com|[a-z0-9.-]+\.storage\.googleapis\.com|storage\.cloud\.google\.com\/[a-z0-9.-]+)/gi,
        severity: "INFO",
        message: "Cloud storage bucket or URL discovered."
    },
    {
        type: "INTERNAL_HOSTNAME",
        pattern: /[a-zA-Z0-9.-]+\.(?:local|lan|internal|corp|dev|test|stag|prod)\b/gi,
        severity: "LOW",
        message: "Potential internal hostname discovered."
    }
];

const scanSensitiveData = async (scriptsOrContent) => {
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

            for (const entry of SENSITIVE_PATTERNS) {
                const matches = content.match(entry.pattern);
                if (matches) {
                    const uniqueMatches = [...new Set(matches)].slice(0, 5);
                    findings.push({
                        type: entry.type,
                        severity: entry.severity,
                        source: source,
                        matches: uniqueMatches,
                        message: entry.message
                    });
                }
            }
        } catch (err) {}
    }

    return findings;
};

module.exports = { scanSensitiveData };
