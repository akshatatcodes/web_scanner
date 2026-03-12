/**
 * Report Summary Generator
 * Creates a natural language summary of the scan results.
 */

function generateSummary(scanResults) {
    const totalCookies = scanResults.cookieSecurity.length;
    const cookieWarnings = scanResults.cookieSecurity.filter(c => c.risk !== 'LOW').length;
    const cookieHighRisks = scanResults.cookieSecurity.filter(c => c.risk === 'HIGH').length;

    const scriptWarnings = scanResults.suspiciousScripts.length;
    const scriptHighRisks = scanResults.suspiciousScripts.filter(s => s.risk === 'HIGH').length;

    const totalHighRisks = cookieHighRisks + scriptHighRisks;
    const totalWarnings = cookieWarnings + scriptWarnings;

    let message = `We detected ${totalCookies} cookies and ${scriptWarnings} suspicious script issues during the scan. `;
    
    if (totalWarnings === 0) {
        message += "The website follows solid security practices for scripts and cookies.";
    } else {
        message += `${totalWarnings} security settings could be improved, with ${totalHighRisks} identified as high risk.`;
    }

    const recommendation = totalHighRisks > 0 
        ? "We recommend addressing the high-risk issues (especially script-related threats) immediately."
        : "While no critical vulnerabilities were found, following the recommended security best practices will further enhance your site's safety.";

    return {
        totalCookies,
        totalWarnings,
        totalHighRisks,
        message,
        recommendation,
        scanDuration: scanResults.scanDuration,
        timestamp: scanResults.timestamp
    };
}

module.exports = { generateSummary };
