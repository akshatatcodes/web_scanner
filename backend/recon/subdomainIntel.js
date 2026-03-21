/**
 * Subdomain Intelligence Mapping
 * Classifies subdomains into logical infrastructure types to prioritize attack phases.
 */

const classifySubdomain = (sub) => {
    const s = sub.toLowerCase();
    
    // High Value / Critical Infrastructure (Score 30-50 later)
    if (/(admin|internal|intranet|secure|vpn|corp|private|portal|cpanel)/.test(s)) return "critical";
    if (/(dev|staging|test|qa|beta|sandbox|uat|demo)/.test(s)) return "high";
    if (/(api|graph|gql|ws|socket|service)/.test(s)) return "high";
    
    // Auth / SSO
    if (/(auth|sso|login|oauth|jwt|identity)/.test(s)) return "critical";
    
    // Low Value / Static / Marketing (Score 0-5)
    if (/(cdn|static|assets|media|img|images|css|js|blog|news|www)/.test(s)) return "low";
    
    // Default fallback
    return "medium";
};

const mapSubdomains = (subdomains) => {
    const mapping = {};
    for (const sub of subdomains) {
        mapping[sub] = {
            type: classifySubdomain(sub),
            risk: classifySubdomain(sub)
        };
    }
    return mapping;
};

module.exports = { classifySubdomain, mapSubdomains };
