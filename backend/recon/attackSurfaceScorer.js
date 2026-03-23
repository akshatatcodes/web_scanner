/**
 * Attack Surface Scoring Engine
 * Combines all intelligence into a prioritized attack risk score.
 */

const calculateScore = (intel) => {
    let score = 0;
    const reasons = [];

    // 1. Subdomain Intelligence Scoring
    if (intel.subdomainRisk === 'critical') {
        score += 40;
        reasons.push("Critical infrastructure subdomain pattern (e.g. admin/auth)");
    } else if (intel.subdomainRisk === 'high') {
        score += 30;
        reasons.push("High value subdomain pattern (e.g. dev/staging/api)");
    }

    // 2. Takeover Vulnerabilities
    if (intel.takeover) {
        if (intel.takeover.confirmed) {
            score += 60;
            reasons.push(`Confirmed Takeover explicitly vulnerable via ${intel.takeover.provider}`);
        } else {
            score += 30;
            reasons.push(`Dangling CNAME points to third-party cloud (${intel.takeover.provider})`);
        }
    }

    // 3. Wayback Parameter Surface
    if (intel.waybackData && intel.waybackData.parameters.length > 0) {
        const paramCount = intel.waybackData.parameters.length;
        if (paramCount > 10) {
            score += 25;
            reasons.push(`Massive parameter exposure in Wayback (${paramCount} params)`);
        } else if (paramCount > 2) {
            score += 15;
            reasons.push(`Historical parameter injection points found (${paramCount} params)`);
        }
    }

    // 4. Infrastructure & ASN Pivoting
    if (intel.asn && intel.asn.isCloud === false) {
        score += 15;
        reasons.push(`Direct infrastructure exposed (ASN: ${intel.asn.organization})`);
    }

    // 5. CDN Bypass (Critical)
    if (intel.cdnBypass && intel.cdnBypass.bypassed) {
        score += 50;
        reasons.push(`WAF/CDN bypassed! Real origin IP exposed: ${intel.cdnBypass.originIp}`);
    }

    // 6. JS Deep Analysis
    if (intel.jsData && intel.jsData.stats && intel.jsData.stats.totalSecrets > 0) {
        score += 40;
        reasons.push(`Hardcoded secrets/tokens discovered in JS sources (${intel.jsData.stats.totalSecrets} found)`);
    } else if (intel.jsData && intel.jsData.stats && intel.jsData.stats.totalEndpoints > 10) {
        score += 15;
        reasons.push(`Massive internal endpoint exposure in JS bundles`);
    }

    // 7. GitHub Leaks
    if (intel.githubData && intel.githubData.leaksFound) {
        score += 60;
        reasons.push(`Confirmed secrets/source code leaks on GitHub (${intel.githubData.totalCount} matches)`);
    }

    // 8. Behavioral Exploitation Confirmations
    if (intel.behaviorAnomalies && intel.behaviorAnomalies.length > 0) {
        let maxVulnScore = 0;
        intel.behaviorAnomalies.forEach(anom => {
            if (anom.confidence === "CRITICAL") maxVulnScore = Math.max(maxVulnScore, 80);
            if (anom.confidence === "HIGH") maxVulnScore = Math.max(maxVulnScore, 50);
            if (anom.confidence === "LOW") maxVulnScore = Math.max(maxVulnScore, 15);
        });
        
        if (maxVulnScore > 0) {
            score += maxVulnScore;
            reasons.push(`Behavioral exploiting confirmed active vulnerabilities! (+${maxVulnScore} Risk)`);
        }
    }

    // Cap at 100 for percentage scale
    const finalScore = Math.min(score, 100);

    let priority = "LOW";
    if (finalScore >= 80) priority = "ATTACK FIRST (CRITICAL)";
    else if (finalScore >= 50) priority = "HIGH VALUE";
    else if (finalScore >= 30) priority = "MODERATE INTEREST";

    return {
        riskScore: finalScore,
        priority: priority,
        reasons: reasons
    };
};

module.exports = { calculateScore };
