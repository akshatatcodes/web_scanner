const scanJWT = async (storageData) => {
    const findings = [];
    const JWT_REGEX = /ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;

    const allStrings = typeof storageData === 'string' ? storageData : JSON.stringify(storageData);
    const matches = allStrings.match(JWT_REGEX) || [];

    const uniqueJwts = [...new Set(matches)];

    for (const jwt of uniqueJwts) {
        try {
            const parts = jwt.split('.');
            if (parts.length < 2) continue;

            const headerStr = Buffer.from(parts[0], 'base64').toString('ascii');
            const payloadStr = Buffer.from(parts[1], 'base64').toString('ascii');
            
            const header = JSON.parse(headerStr);
            const payload = JSON.parse(payloadStr);
            const signature = parts[2];

            if (header.alg && header.alg.toLowerCase() === 'none') {
                findings.push({
                    type: "JWT_MISCONFIGURATION",
                    severity: "CRITICAL",
                    confidence: "Confirmed",
                    message: `Algorithm set to 'none' (Allows trivial authentication bypassing)`,
                    evidence: `Header: ${JSON.stringify(header)}`
                });
            }

            if (!signature || signature.length === 0) {
                findings.push({
                    type: "JWT_MISCONFIGURATION",
                    severity: "CRITICAL",
                    confidence: "High Probability",
                    message: `Missing signature block entirely`,
                    evidence: `Token structure lacks verifiable 3rd component.`
                });
            }

            if (header.alg === 'HS256') {
                findings.push({
                    type: "JWT_MISCONFIGURATION",
                    severity: "MEDIUM",
                    confidence: "Potential",
                    message: `Token uses HS256 (May be vulnerable to symmetric key brute-forcing)`,
                    evidence: `Alg: HS256`
                });
            }

            if (!payload.exp) {
                findings.push({
                    type: "JWT_MISCONFIGURATION",
                    severity: "LOW",
                    confidence: "Confirmed",
                    message: `Token never expires (Missing 'exp' claim)`,
                    evidence: `Token TTL is infinite.`
                });
            } else {
                const now = Math.floor(Date.now() / 1000);
                if (payload.exp - now > 31536000) { // > 1 year
                    findings.push({
                        type: "JWT_MISCONFIGURATION",
                        severity: "LOW",
                        confidence: "Confirmed",
                        message: `Token expiration is insecurely long (> 1 year)`,
                        evidence: `Exp Timestamp: ${payload.exp}`
                    });
                }
            }

            const sensitiveRegex = /(password|secret|ssn|role|admin|key)/i;
            if (sensitiveRegex.test(payloadStr)) {
                findings.push({
                    type: "JWT_MISCONFIGURATION",
                    severity: "MEDIUM",
                    confidence: "Confirmed",
                    message: `Sensitive/Privileged claims stored within plaintext Base64 payload`,
                    evidence: `Matched regex pattern for standard administrative or credential keys.`
                });
            }
        } catch(e) {
            // Ignore parse errors from generic base64 strings mimicking JWTs
        }
    }
    return findings; // Ensure it unconditionally returns array
};

module.exports = { scanJWT };
