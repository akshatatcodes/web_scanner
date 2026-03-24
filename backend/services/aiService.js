/**
 * AI Service for Vulnerability Analysis
 * Supports OpenAI, Gemini (simulated), and a high-fidelity Mock mode.
 */

const MOCK_DELAY = 1500;

const axios = require('axios');

class AIService {
    constructor() {
        this.geminiKey = process.env.GEMINI_API_KEY || null;
        this.openAiKey = process.env.OPENAI_API_KEY || null;
    }

    /**
     * Analyze a finding using AI.
     * @param {object} finding - The finding object with .proof, .message, etc.
     */
    async analyze(finding) {
        if (!this.geminiKey && !this.openAiKey) {
            return this.getMockAnalysis(finding);
        }

        try {
            if (this.geminiKey) {
                return await this.callGemini(finding);
            } else if (this.openAiKey) {
                return await this.callOpenAI(finding);
            }
        } catch (error) {
            console.error('[AI Service Error]:', error.response?.data || error.message);
            // Fallback to mock if API fails (e.g., rate limits)
            const fallback = await this.getMockAnalysis(finding);
            fallback.explanation = `[API Error: ${error.message}] ` + fallback.explanation;
            return fallback;
        }
    }

    async callGemini(finding) {
        const payload = `Analyze this vulnerability finding: ${JSON.stringify(finding)}. Explain the security impact, determine if it's a false positive based on the proof, and provide a secure fix (code snippet). Respond entirely in clean JSON format without markdown wrapping, using exactly these keys: "confidence" (float), "isFalsePositive" (boolean), "explanation" (string), "fix" (string).`;
        
        // Retry logic for Google API 503 limits
        let response;
        for (let attempt = 1; attempt <= 3; attempt++) {
            try {
                response = await axios.post(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${this.geminiKey}`, {
                    contents: [{ parts: [{ text: payload }] }]
                });
                break; // success
            } catch (err) {
                if (err.response?.status === 503 && attempt < 3) {
                    await new Promise(r => setTimeout(r, 2000 * attempt));
                } else {
                    throw err;
                }
            }
        }
        
        const textResponse = response.data.candidates[0].content.parts[0].text;
        const cleanJson = textResponse.replace(/^```json\n?|\n?```$/gm, '').trim();
        const parsed = JSON.parse(cleanJson);
        
        return {
            ...parsed,
            analyzedAt: new Date().toISOString(),
            provider: 'Gemini-2.5-Flash'
        };
    }

    async callOpenAI(finding) {
        // Automatically determine if it's Groq by key prefix
        const isGroq = this.openAiKey.startsWith('gsk_');
        const baseURL = isGroq ? 'https://api.groq.com/openai/v1/chat/completions' : 'https://api.openai.com/v1/chat/completions';
        const model = isGroq ? 'llama3-8b-8192' : 'gpt-3.5-turbo';

        const response = await axios.post(baseURL, {
            model: model,
            messages: [
                { role: 'system', content: 'You are an elite application security engineer. Return exactly one JSON object resolving the vulnerability with keys: "confidence" (float), "isFalsePositive" (boolean), "explanation" (string), "fix" (string).' },
                { role: 'user', content: `Analyze: ${JSON.stringify(finding)}` }
            ],
            response_format: { type: "json_object" }
        }, {
            headers: { 'Authorization': `Bearer ${this.openAiKey}`, 'Content-Type': 'application/json' }
        });
        
        const parsed = JSON.parse(response.data.choices[0].message.content);
        return {
            ...parsed,
            analyzedAt: new Date().toISOString(),
            provider: isGroq ? 'Groq Llama-3' : 'OpenAI GPT'
        };
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
            provider: 'Mock-Engine-v1'
        };
    }
}

module.exports = new AIService();
