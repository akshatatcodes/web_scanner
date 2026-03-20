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
    },
    EVAL_USAGE: {
        title: "Execution of Arbitrary Code (eval)",
        explanation: "The script uses eval(), which executes string content as JavaScript. This is extremely dangerous if the string contains any user-controlled data.",
        impact: "Allows attackers to run any code in the user's browser, leading to full account compromise or data theft.",
        recommendation: "Avoid eval() at all costs. Use JSON.parse() for data or direct property access instead."
    },
    DOCUMENT_WRITE: {
        title: "Unsafe DOM Injection (document.write)",
        explanation: "The script uses document.write() to inject content. This is a legacy API that can be easily abused to inject malicious scripts.",
        impact: "Enables Cross-Site Scripting (XSS) by writing untrusted data directly into the page's HTML stream.",
        recommendation: "Use modern DOM APIs like document.createElement() and element.textContent instead."
    },
    INNER_HTML_ASSIGNMENT: {
        title: "Unsafe HTML Assignment (innerHTML)",
        explanation: "The script assigns content to innerHTML. If this content is not properly sanitized, it can execute scripts embedded in the HTML.",
        impact: "Common vector for DOM-based XSS attacks.",
        recommendation: "Use element.textContent for plain text or use a trusted sanitization library (like DOMPurify) before using innerHTML."
    },
    OUTER_HTML_ASSIGNMENT: {
        title: "Unsafe OuterHTML Assignment",
        explanation: "The script replaces an entire element using outerHTML, which can lead to script injection if the replacement string is untrusted.",
        impact: "Similar to innerHTML, it creates a significant XSS risk.",
        recommendation: "Avoid replacing elements with raw HTML strings. Use DOM manipulation methods instead."
    },
    INSERT_ADJACENT_HTML: {
        title: "Dangerous HTML Insertion (insertAdjacentHTML)",
        explanation: "The script uses insertAdjacentHTML to add content to the DOM. This bypasses typical safety checks.",
        impact: "Allows attackers to inject malicious elements into specific page locations.",
        recommendation: "Use safer alternatives like insertAdjacentElement or sanitize the HTML input."
    },
    TIMER_STRING_EXEC: {
        title: "String-based Timer Execution",
        explanation: "Passing a string to setTimeout or setInterval causes the browser to evaluate it as code, similar to eval().",
        impact: "Can be used to execute delayed malicious payloads.",
        recommendation: "Pass a function reference instead of a string (e.g., setTimeout(() => { ... }, 1000))."
    },
    DOM_XSS_PATH: {
        title: "Potential DOM XSS Attack Path",
        explanation: "A dangerous combination was found: a user-controllable source (like location.hash) flows into a dangerous sink (like innerHTML).",
        impact: "This is a highly exploitable vulnerability. Attackers can craft URLs that execute code automatically when visited.",
        recommendation: "Sanitize all data from location, URL, or postMessage before passing it to any DOM-writing function."
    },
    MISSING_CSP: {
        title: "Content Security Policy (CSP) Not Found",
        explanation: "The website does not provide a Content Security Policy header, which is a critical second line of defense against XSS.",
        impact: "Without CSP, any XSS vulnerability can be fully exploited to steal data or inject malicious scripts from external domains.",
        recommendation: "Implement a strict Content Security Policy to restrict script sources and prevent inline script execution."
    },
    BLACKLISTED: {
        title: "URL Detected in Threat Database",
        explanation: "This URL is flagged by Google Safe Browsing as potentially dangerous (malware, phishing, or unwanted software).",
        impact: "Visitors may be blocked by their browser or exposed to malicious attacks, theft of credentials, or malware infections.",
        recommendation: "Immediately investigate the site's content and security logs. If you believe this is an error, use the Google Search Console to request a review."
    },
    MISSING_SPF: {
        title: "Missing SPF Record",
        explanation: "The domain does not have a Sender Policy Framework (SPF) record in its DNS configuration.",
        impact: "Without SPF, it is much easier for attackers to send spoofed emails that appear to come from your domain, potentially leading to phishing and reputation damage.",
        recommendation: "Add a TXT record to your DNS indicating which mail servers are authorized to send email on behalf of your domain."
    },
    MISSING_DMARC: {
        title: "Missing DMARC Record",
        explanation: "The domain is missing a DMARC (Domain-based Message Authentication, Reporting, and Conformance) policy.",
        impact: "DMARC provides instructions to receiving mail servers on how to handle emails that fail SPF/DKIM checks. Without it, your domain is more vulnerable to impersonation.",
        recommendation: "Create a DMARC record (starting with v=DMARC1) to specify how email servers should handle unauthenticated emails."
    },
    MISSING_DKIM: {
        title: "Missing DKIM Records",
        explanation: "No standard DomainKeys Identified Mail (DKIM) records were found for this domain.",
        impact: "DKIM adds a cryptographic signature to emails, verifying they weren't altered in transit. Missing DKIM increases the risk of mail being marked as spam or spoofed.",
        recommendation: "Generate a DKIM public/private key pair and add the public key as a TXT record in your DNS settings."
    },
    SQL_INJECTION: {
        title: "SQL Injection (SQLi)",
        explanation: "The application fails to properly sanitize user input before using it in a database query. Attackers can 'inject' their own SQL commands.",
        impact: "Allow attackers to bypass authentication, read sensitive data (user lists, passwords), or even delete entire databases.",
        recommendation: "Use parameterized queries (prepared statements) and never concatenate user input directly into SQL strings."
    },
    COMMAND_INJECTION: {
        title: "OS Command Injection",
        explanation: "The web application passes unvalidated user input to the operating system's command shell.",
        impact: "Allows attackers to execute arbitrary system commands (like 'whoami', 'cat /etc/passwd'), potentially leading to full server takeover.",
        recommendation: "Avoid calling system commands directly. Use language-specific APIs instead, or strictly whitelist allowed characters (alphanumeric only)."
    },
    IDOR_VULNERABILITY: {
        title: "Insecure Direct Object Reference (IDOR)",
        explanation: "The application reveals direct access to objects (like a user ID or order number) in the URL without checking if the user is authorized to see them.",
        impact: "Users can change IDs in the URL to view other people's private data, such as profiles, invoices, or private messages.",
        recommendation: "Implement strict access control checks for every object request. Ensure the 'Current User' owns the requested object ID."
    },
    JWT_MISCONFIG: {
        title: "JWT Security Misconfiguration",
        explanation: "The JSON Web Token (JWT) is either poorly signed, uses a weak algorithm, or contains sensitive data in its payload.",
        impact: "Could allow attackers to forge valid tokens or steal session information, leading to unauthorized account access.",
        recommendation: "Use strong signing algorithms (RS256), keep secrets extremely secure, and never put PII in a JWT payload."
    }
};

module.exports = { issueExplanations };
