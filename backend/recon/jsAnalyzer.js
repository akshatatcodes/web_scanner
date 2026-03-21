const axios = require('axios');
const { safeRequest, pLimit } = require('./utils');

const PATTERNS = {
    endpoints: /(?:"|'|`)((\/api\/|\/v[1-9]\/|\/admin\/|\/graphql)[a-zA-Z0-9_\-\/]+)(?:"|'|`)/gi,
    aws_keys: /AKIA[0-9A-Z]{16}/g,
    firebase: /AIza[0-9A-Za-z\-_]{35}/g,
    jwt: /ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    generic_secrets: /(?:apiKey|api_key|secret|token|password|auth|access_token)[\s:=]+['"]([A-Za-z0-9_\-]{16,})['"]/gi
};

const extractFromContent = (content, url) => {
    const findings = {
        endpoints: new Set(),
        secrets: new Set(),
        jwts: new Set(),
        source: url
    };

    if (!content) return findings;

    // Endpoints
    let m;
    while ((m = PATTERNS.endpoints.exec(content)) !== null) {
        if (m[1]) findings.endpoints.add(m[1]);
    }

    // AWS
    const aws = content.match(PATTERNS.aws_keys) || [];
    aws.forEach(k => findings.secrets.add(`AWS Key: ${k}`));

    // Firebase
    const fb = content.match(PATTERNS.firebase) || [];
    fb.forEach(k => findings.secrets.add(`Firebase: ${k}`));

    // JWT
    const jwt = content.match(PATTERNS.jwt) || [];
    jwt.forEach(k => findings.jwts.add(`${k.substring(0, 20)}...[TRUNCATED]`));

    // Generic
    while ((m = PATTERNS.generic_secrets.exec(content)) !== null) {
        if (m[1]) findings.secrets.add(`Generic Token: ${m[1]}`);
    }

    return findings;
};

const analyzeJS = async (scripts) => {
    const limit = pLimit(5); // Throttle JS fetching
    const allFindings = [];

    const fetchPromises = scripts.map(script => limit(async () => {
        let content = script.content;
        const sourceUrl = script.src || 'inline_script';

        if (!content && script.src) {
            // It's an external script that hasn't been fetched yet
            try {
                const res = await safeRequest(() => axios.get(script.src, { timeout: 10000, maxContentLength: 5000000 }), 2);
                if (res && res.data && typeof res.data === 'string') {
                    content = res.data;
                }
            } catch(e) {}
        }

        const extracted = extractFromContent(content, sourceUrl);
        if (extracted.endpoints.size > 0 || extracted.secrets.size > 0 || extracted.jwts.size > 0) {
            allFindings.push({
                source: extracted.source,
                endpoints: Array.from(extracted.endpoints),
                secrets: Array.from(extracted.secrets),
                jwts: Array.from(extracted.jwts)
            });
        }
    }));

    await Promise.all(fetchPromises);

    // Aggregate
    let totalEndpoints = 0;
    let totalSecrets = 0;
    allFindings.forEach(f => {
        totalEndpoints += f.endpoints.length;
        totalSecrets += f.secrets.length + f.jwts.length;
    });

    return {
        analyzedFiles: scripts.length,
        findingDetails: allFindings,
        stats: { totalEndpoints, totalSecrets }
    };
};

module.exports = { analyzeJS };
