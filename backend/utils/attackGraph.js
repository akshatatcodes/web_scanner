/**
 * PRO Attack Graph Engine
 * Connects standardized vulnerabilities into chained exploit paths.
 */

const attackRules = [
  {
    id: "SSRF_TO_RCE",
    name: "SSRF to Remote Code Execution (RCE)",
    conditions: ["ssrf", "internal_port_open"],
    severity: "CRITICAL",
    path: ["SSRF Vulnerability", "Internal Network Access", "Service Exploitation", "RCE"],
    description: "Server-Side Request Forgery allows access to internal management interfaces or databases, which can be exploited for Remote Code Execution.",
    confidence: 0.9
  },
  {
    id: "ACCOUNT_TAKEOVER",
    name: "Full Account Takeover (ATO) Chain",
    conditions: ["idor", "jwt_misconfig"],
    severity: "CRITICAL",
    path: ["IDOR Vulnerability", "JWT Signature Weakness", "Identity Spoofing", "Account Takeover"],
    description: "Combining IDOR to discover user IDs with JWT weaknesses allows an attacker to forge tokens and take over any user account.",
    confidence: 0.85
  },
  {
    id: "SESSION_HIJACK_CHAIN",
    name: "Cross-Site Session Hijacking",
    conditions: ["xss_risk", "missing_httponly"],
    severity: "HIGH",
    path: ["XSS Vulnerability", "Cookie Theft (No HttpOnly)", "Session Hijack"],
    description: "XSS can be used to steal session cookies if the HttpOnly flag is missing, leading to full session takeover.",
    confidence: 0.95
  },
  {
    id: "DB_EXFILTRATION",
    name: "Database Exfiltration & Admin Bypass",
    conditions: ["sqli", "auth_bypass"],
    severity: "CRITICAL",
    path: ["SQL Injection", "Authentication Bypass", "Database Administrative Access", "Data Exfiltration"],
    description: "SQL Injection provides data access, while Auth Bypass provides the administrative context needed to exfiltrate the entire database.",
    confidence: 0.9
  },
  {
    id: "ADVANCED_PHISHING",
    name: "Advanced Phishing & Malware Delivery",
    conditions: ["open_redirect", "missing_csp"],
    severity: "HIGH",
    path: ["Open Redirect", "Missing CSP Defense", "Malicious Site Redirection", "Credential Theft"],
    description: "Open redirects on a site without CSP can be used to build highly convincing phishing attacks or deliver malware payloads.",
    confidence: 0.8
  }
];

/**
 * Analyzes normalized vulnerabilities to find matching attack chains.
 * @param {Array} vulnerabilities Standardized list of findings { type, severity, evidence }
 */
function analyzeAttackGraph(vulnerabilities) {
  const foundTypes = vulnerabilities.map(v => v.type);
  const chains = [];

  for (const rule of attackRules) {
    // Check if all conditions for the rule are met
    const matchedConditions = rule.conditions.filter(cond => foundTypes.includes(cond));
    const isMatch = matchedConditions.length === rule.conditions.length;

    if (isMatch) {
      // Collect evidence for each condition in the chain
      const evidence = {};
      rule.conditions.forEach(cond => {
        const finding = vulnerabilities.find(v => v.type === cond);
        evidence[cond] = finding ? finding.evidence : "Evidence not captured";
      });

      chains.push({
        id: rule.id,
        name: rule.name,
        severity: rule.severity, // Escalated severity
        path: rule.path,
        description: rule.description,
        evidence: evidence,
        confidence: rule.confidence,
        timestamp: new Date().toISOString()
      });
    }
  }

  return chains;
}

module.exports = { analyzeAttackGraph, attackRules };
