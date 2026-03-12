/**
 * Security Explanation Engine
 * Converts technical issue codes into human-readable explanations.
 */

const issueExplanations = {
    MISSING_SECURE: {
        title: "Cookie not restricted to HTTPS",
        explanation: "This cookie can be transmitted over unencrypted HTTP connections. Attackers on the same network (such as public Wi-Fi) may intercept it.",
        impact: "If the cookie contains sensitive data, attackers could capture it and impersonate the user.",
        recommendation: "Enable the Secure flag so the cookie is only sent over HTTPS connections."
    },
    MISSING_HTTPONLY: {
        title: "Cookie accessible by browser scripts",
        explanation: "This cookie can be accessed by JavaScript running on the website.",
        impact: "If the website has a cross-site scripting (XSS) vulnerability, attackers could steal the cookie.",
        recommendation: "Enable the HttpOnly flag to prevent JavaScript access."
    },
    MISSING_SAMESITE: {
        title: "Missing SameSite protection",
        explanation: "The cookie does not specify a SameSite policy, which helps protect against cross-site request forgery (CSRF) attacks.",
        impact: "Attackers may be able to trick the browser into sending cookies in cross-site requests.",
        recommendation: "Set SameSite=Lax or SameSite=Strict depending on application requirements."
    },
    SAMESITE_NONE_INSECURE: {
        title: "Insecure SameSite=None Combination",
        explanation: "The cookie is set to SameSite=None but is missing the Secure flag.",
        impact: "Modern browsers will reject this cookie, potentially breaking site functionality. It also exposes the cookie to cross-site attacks.",
        recommendation: "Always set the Secure flag when using SameSite=None."
    },
    LONG_EXPIRY: {
        title: "Cookie stored for a long time",
        explanation: "The cookie remains valid for a long period (more than 6 months).",
        impact: "If the cookie is stolen, it could remain usable for an extended period, increasing the window of risk.",
        recommendation: "Reduce the cookie lifetime to the minimum necessary for the application."
    },
    BROAD_DOMAIN: {
        title: "Cookie shared across many subdomains",
        explanation: "The cookie's domain scope is too broad (e.g., starts with a dot like .example.com).",
        impact: "If any subdomain is compromised (even a less secure development or test site), attackers may access this cookie.",
        recommendation: "Restrict the cookie domain to only the specific subdomain that requires it."
    },
    SENSITIVE_DATA: {
        title: "Potential sensitive data in plaintext",
        explanation: "The cookie value appears to contain sensitive keywords (like 'admin' or 'token') in an unencrypted or easily readable format.",
        impact: "Anyone with access to the browser or intercepted traffic can easily read sensitive information.",
        recommendation: "Encrypt or hash sensitive data before storing it in cookies, or use purely opaque session identifiers."
    },
    LOW_ENTROPY: {
        title: "Weak or Predictable Session ID",
        explanation: "The session identifier (cookie value) is too short or consists of predictable patterns (like only numbers).",
        impact: "Attackers might be able to 'guess' active session IDs using brute-force or prediction algorithms, leading to unauthorized access.",
        recommendation: "Use a cryptographically secure random number generator to produce long, high-entropy session IDs (at least 128 bits)."
    },
    ROOT_PATH: {
        title: "Cookie path scope is root (/)",
        explanation: "The cookie is sent to every page on the domain.",
        impact: "This increases the 'attack surface' as the cookie is sent even to parts of the site that don't need it.",
        recommendation: "Restrict the cookie path to the specific subdirectory where it is used (e.g., /app)."
    },
    UNKNOWN_DOMAIN: {
        title: "External Script from Unknown Domain",
        explanation: "This script is loaded from a third-party domain that is not on the trusted list.",
        impact: "If the external server becomes compromised, attackers could inject malicious code (like payment skimmers or crypto-miners) into your website.",
        recommendation: "Only load scripts from trusted providers and consider using Subresource Integrity (SRI) hashes."
    },
    MALICIOUS_PATTERN: {
        title: "Potential Malicious Script Signature",
        explanation: "The script's content matches known patterns used by crypto-miners, credit card skimmers (Magecart), or obfuscation tools.",
        impact: "This is a high-risk finding. Malicious code could be stealing user data or using their device's resources without permission.",
        recommendation: "Immediately investigate the source of this script and remove it if it is not legitimate."
    },
    RISKY_API: {
        title: "Use of Dangerous JavaScript APIs",
        explanation: "The script uses risky functions like eval() or document.write(), which are often used to execute hidden malicious code.",
        impact: "These APIs can bypass security filters and make the website vulnerable to Cross-Site Scripting (XSS) attacks.",
        recommendation: "Replace dangerous APIs with safer alternatives (e.g., JSON.parse instead of eval, or DOM manipulation instead of document.write)."
    }
};

module.exports = { issueExplanations };
