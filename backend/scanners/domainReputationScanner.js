const axios = require('axios');

/**
 * Domain Reputation Scanner (Google Safe Browsing)
 * Checks if a domain is malicious, phishing, or a malware host.
 */
async function scan(url) {
    const apiKey = process.env.SAFE_BROWSING_API_KEY || process.env.GOOGLE_SAFE_BROWSING_KEY;
    
    if (!apiKey) {
        return { status: "unknown", error: "Missing API Key" };
    }

    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

    const body = {
        client: {
            clientId: "super-analyzer",
            clientVersion: "1.0"
        },
        threatInfo: {
            threatTypes: [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
        }
    };

    try {
        const response = await axios.post(endpoint, body);

        if (response.data.matches) {
            return {
                status: "malicious",
                threats: response.data.matches.map(m => ({
                    type: m.threatType,
                    platform: m.platformType
                })),
                riskLevel: "HIGH"
            };
        }

        return {
            status: "clean",
            threats: [],
            riskLevel: "LOW"
        };
    } catch (error) {
        console.error('[Domain Reputation] Error:', error.message);
        return {
            status: "unknown",
            threats: [],
            error: error.message
        };
    }
}

module.exports = { scan };
