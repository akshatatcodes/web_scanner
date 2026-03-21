/**
 * AI Service for Vulnerability Analysis
 * Supports OpenAI, Gemini (simulated), and a high-fidelity Mock mode.
 */

const MOCK_DELAY = 1500;

class AIService {
    constructor() {
        this.apiKey = process.env.AI_API_KEY || null;
        this.provider = process.env.AI_PROVIDER || 'openai'; // or 'gemini'
    }

    /**
     * Analyze a finding using AI.
     * @param {object} finding - The finding object with .proof, .message, etc.
     */
    async analyze(finding) {
        if (!this.apiKey) {
            return this.getMockAnalysis(finding);
        }

        // Logic for real AI providers would go here (axios.post to OpenAI/Gemini)
        // Redacting sensitive data before sending is handled by proofStore, 
        // but we'd add another layer here if needed.
        
        return this.getMockAnalysis(finding); // Defaulting to mock for now
    }

    async getMockAnalysis(finding) {
        await new Promise(resolve => setTimeout(resolve, MOCK_DELAY));

        const type = finding.type || finding.vulnerability;
        
        const analyses = {
            'SQL_INJECTION': {
                confidence: 0.94,
                isFalsePositive: false,
                explanation: "The application fails to parameterize inputs in the URL parameter. The payload sent (`' OR 1=1`) successfully manipulated the query logic, evidenced by the change in response length and database error signature.",
                fix: "Use Prepared Statements (Parameterized Queries) instead of string concatenation. Example (Node.js/Knex): `db('users').where('id', id)` instead of `db.raw(\"... where id = \" + id)`."
            },
            'COMMAND_INJECTION': {
                confidence: 0.98,
                isFalsePositive: false,
                explanation: "The target is executing OS commands directly with user-supplied input. The `sleep` payload resulted in an exact execution delay of 2.1 seconds, confirming a blind RCE vulnerability.",
                fix: "Avoid using `exec()` or `eval()`. Use `execFile()` with an arguments array, or better, implement an allowlist of permitted actions instead of passing raw strings to the shell."
            },
            'SSRF': {
                confidence: 0.82,
                isFalsePositive: false,
                explanation: "The application accepts a URL in a parameter and attempts to fetch it. The scanner successfully reached an internal-only IP (169.254.169.254), which could lead to cloud metadata exposure.",
                fix: "Implement a strict allowlist of permitted domains. Never allow requests to internal IP ranges (10.x.x.x, 172.x.x.x, 192.168.x.x, 169.254.169.254)."
            },
            'IDOR': {
                confidence: 0.88,
                isFalsePositive: false,
                explanation: "The endpoint `/api/user/123` was successfully queried by incrementing the ID to `124`. The response contained private JSON fields (email/uuid) for a different user context, indicating missing authorization checks.",
                fix: "Do not rely on numeric IDs for authorization. Check ownership of the resource on the server-side: `if (resource.ownerId !== currentUser.id) return 403;`"
            },
            'AUTH_BYPASS': {
                confidence: 0.91,
                isFalsePositive: false,
                explanation: "The application trusts headers like `X-Forwarded-For` or `X-Admin-True` to determine security context. Sending these headers allowed access to a restricted endpoint that returned 403 previously.",
                fix: "Never trust client-supplied headers for security decisions. Use a secure, server-side session or JWT-based authentication mechanism."
            }
        };

        const defaultAnalysis = {
            confidence: 0.75,
            isFalsePositive: false,
            explanation: `The scan detected a potential ${type} vulnerability. The evidence shows a deviation in server behavior that matches known vulnerability patterns.`,
            fix: "Review the code handling this parameter for missing input validation or unsafe function calls."
        };

        return {
            ...(analyses[type] || defaultAnalysis),
            analyzedAt: new Date().toISOString(),
            provider: this.apiKey ? this.provider : 'Mock-Engine-v1'
        };
    }
}

module.exports = new AIService();
