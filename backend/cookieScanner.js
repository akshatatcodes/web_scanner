/**
 * Cookie Security Analyzer
 * Performs professional-grade security checks on cookies.
 */

const SESSION_COOKIE_NAMES = [
    'phpsessid', 'jsessionid', 'asp.net_sessionid', 'connect.sid',
    'session', 'auth_token', 'sid', 'sessid', 'uid', 'user_session'
];

const SENSITIVE_KEYWORDS = ['admin', 'root', 'password', 'pwd', 'secret', 'token'];

async function analyze(cookies) {
    const results = [];

    for (const cookie of cookies) {
        const issues = [];
        let risk = 'LOW';

        // 1. Basic Flags
        if (!cookie.secure) {
            issues.push({ code: 'MISSING_SECURE', severity: 'MEDIUM' });
            risk = 'MEDIUM';
        }

        if (!cookie.httpOnly) {
            issues.push({ code: 'MISSING_HTTPONLY', severity: 'MEDIUM' });
            risk = risk === 'HIGH' ? 'HIGH' : 'MEDIUM';
        }

        if (!cookie.sameSite) {
            issues.push({ code: 'MISSING_SAMESITE', severity: 'LOW' });
        } else if (cookie.sameSite === 'None' && !cookie.secure) {
            issues.push({ code: 'SAMESITE_NONE_INSECURE', severity: 'HIGH' });
            risk = 'HIGH';
        }

        // 2. Session Cookie Detection & Insecurity
        const isSession = SESSION_COOKIE_NAMES.includes(cookie.name.toLowerCase()) || 
                          cookie.name.toLowerCase().includes('session');
        
        if (isSession) {
            if (!cookie.secure || !cookie.httpOnly) {
                // Already added basic flags, but session context makes it HIGH
                risk = 'HIGH';
            }
        }

        // 3. Expiration Check
        if (cookie.expires && cookie.expires !== -1) {
            const now = Date.now() / 1000;
            const lifespan = cookie.expires - now;
            if (lifespan > 60 * 60 * 24 * 30 * 6) { // 6 months
                issues.push({ code: 'LONG_EXPIRY', severity: 'MEDIUM' });
                if (risk === 'LOW') risk = 'MEDIUM';
            }
        }

        // 4. Domain & Path Scope
        if (cookie.domain && cookie.domain.startsWith('.')) {
            issues.push({ code: 'BROAD_DOMAIN', severity: 'MEDIUM' });
            if (risk === 'LOW') risk = 'MEDIUM';
        }
        if (cookie.path === '/') {
            if (isSession) issues.push({ code: 'ROOT_PATH', severity: 'LOW' });
        }

        // 5. Sensitive Data Detection (Basic)
        for (const word of SENSITIVE_KEYWORDS) {
            if (cookie.value.toLowerCase().includes(word) && !isLikelyEncoded(cookie.value)) {
                issues.push({ code: 'SENSITIVE_DATA', severity: 'HIGH' });
                risk = 'HIGH';
                break;
            }
        }

        // 6. Entropy Check
        if (isSession && cookie.value.length < 12) {
            issues.push({ code: 'LOW_ENTROPY', severity: 'HIGH' });
            risk = 'HIGH';
        } else if (isSession && /^\d+$/.test(cookie.value)) {
            issues.push({ code: 'LOW_ENTROPY', severity: 'HIGH' });
            risk = 'HIGH';
        }

        results.push({
            name: cookie.name,
            value: cookie.value.length > 20 ? cookie.value.substring(0, 20) + '...' : cookie.value,
            domain: cookie.domain,
            path: cookie.path,
            secure: cookie.secure,
            httpOnly: cookie.httpOnly,
            sameSite: cookie.sameSite || 'None',
            risk,
            issues
        });
    }

    return results;
}

function isLikelyEncoded(val) {
    // Basic check for base64 or hex
    if (/^[a-f0-9]+$/i.test(val) && val.length > 8) return true; // Hex
    if (/^[A-Za-z0-9+/=]+$/.test(val) && val.length > 12 && val.includes('=')) return true; // Base64
    return false;
}

/**
 * Cookie Fingerprinting Scanner (Keep for compatibility if needed)
 */
async function scan(page) {
    const cookies = await page.cookies();
    const tech = [];

    cookies.forEach(c => {
        if (c.name.startsWith('_ga') || c.name === '_gid') tech.push('Google Analytics');
        if (c.name === '_fbp') tech.push('Facebook Pixel');
        if (c.name.includes('cf_')) tech.push('Cloudflare');
        if (c.name.includes('shopify')) tech.push('Shopify');
        if (c.name === 'PHPSESSID') tech.push('PHP Session');
        if (c.name === 'JSESSIONID') tech.push('Java/JSP Session');
        if (c.name === 'csrftoken') tech.push('Django/Python');
        if (c.name.includes('wp-settings')) tech.push('WordPress');
    });

    return Array.from(new Set(tech));
}

module.exports = { scan, analyze };
