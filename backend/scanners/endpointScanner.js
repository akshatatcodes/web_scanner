const axios = require("axios");
const { URL } = require("url");

// Matches an API path, possibly including origin and query parameters
const API_PATTERN = /((?:https?:\/\/[a-zA-Z0-9.-]+)?(?:\/api\/|\/v[1-9]\/|\/graphql)[a-zA-Z0-9/_-]+(?:\?[a-zA-Z0-9_=-]+(?:&[a-zA-Z0-9_=-]+)*)?)/gi;

const THIRD_PARTY_DOMAINS = [
  "google.com", "googleapis.com", "facebook.com", "fb.com", "twitter.com", 
  "instagram.com", "linkedin.com", "stripe.com", "paypal.com", "github.com",
  "aws.amazon.com", "s3.amazonaws.com", "cloudflare.com", "akamai.com"
];

const TEST_PAYLOADS = ["'", "\"", "<script>alert(1)</script>", "../../../../etc/passwd", "1; SLEEP(5)"];

const checkIsThirdParty = (epUrl, targetHostname) => {
  try {
    const epHostname = new URL(epUrl).hostname;
    // Same origin or subdomain
    if (epHostname === targetHostname || epHostname.endsWith('.' + targetHostname)) {
      return false; 
    }
    // Block known third parties
    for (const tpDomain of THIRD_PARTY_DOMAINS) {
      if (epHostname === tpDomain || epHostname.endsWith('.' + tpDomain)) {
        return true;
      }
    }
    // Any other domain not related to target is treated as third-party to focus on target
    return true; 
  } catch (err) {
    // If it throws, it's a relative path (e.g. /api/users), which belongs to the target
    return false;
  }
};

const extractEndpoints = async (targetUrl, scripts) => {
  const endpoints = new Set();
  let targetHostname = "";
  try {
      targetHostname = new URL(targetUrl).hostname;
  } catch {
      return [];
  }
  
  // 1. Discovery
  for (const script of scripts) {
    if (!script) continue;
    try {
      const res = await axios.get(script, { timeout: 5000 });
      if (typeof res.data !== 'string') continue;

      const matches = res.data.match(API_PATTERN);
      if (matches) {
        for (const m of matches) {
          // Resolve relative paths to absolute using target URL
          let fullUrl = m;
          if (m.startsWith('/')) {
            try {
               fullUrl = new URL(m, targetUrl).href;
            } catch (e) {
               continue;
            }
          }

          if (!checkIsThirdParty(fullUrl, targetHostname)) {
            endpoints.add(fullUrl);
          }
        }
      }
    } catch (err) {}
  }

  const results = [];

  // 2. Fuzzing & Anomaly Detection
  for (const ep of endpoints) {
    let riskScore = 1; // base score
    let severity = "INFO";
    let message = "Hidden API endpoint discovered in JavaScript.";
    let anomalies = [];
    let paramCount = 0;

    try {
      const epUrlObj = new URL(ep);
      const testParams = new URLSearchParams(epUrlObj.search);
      
      paramCount = Array.from(testParams.keys()).length;
      
      // Auto-test with query parameters if none exist
      if (paramCount === 0) {
          testParams.append("id", "1");
          testParams.append("page", "1");
          paramCount = 2; 
      }

      riskScore += paramCount; // More params = higher risk
      epUrlObj.search = testParams.toString();
      
      // Send a baseline request
      const baselineUrl = epUrlObj.href;
      const baselineRes = await axios.get(baselineUrl, { validateStatus: null, timeout: 5000 });
      const baselineLength = baselineRes.data ? JSON.stringify(baselineRes.data).length : 0;
      const baselineStatus = baselineRes.status;

      // Inject payload into first parameter
      const firstParam = Array.from(testParams.keys())[0];
      if (firstParam) {
          testParams.set(firstParam, TEST_PAYLOADS[0]); // inject "'"
          epUrlObj.search = testParams.toString();
          const payloadUrl = epUrlObj.href;

          const payloadRes = await axios.get(payloadUrl, { validateStatus: null, timeout: 5000 });
          const payloadLength = payloadRes.data ? JSON.stringify(payloadRes.data).length : 0;

          // Detect anomalies
          if (payloadRes.status === 500 && baselineStatus !== 500) {
              anomalies.push("HTTP 500 Error induced by payload (Possible Injection)");
              riskScore += 5;
          }
          if (Math.abs(payloadLength - baselineLength) > 500 && payloadRes.status !== 404) {
              anomalies.push("Significant content length deviation with payload");
              riskScore += 2;
          }
      }

    } catch (err) {
      // Ignore network errors or URL parse errors during fuzzing
    }

    if (riskScore >= 5) {
      severity = "HIGH";
      message = "High risk API endpoint with parameters causing anomalous behavior.";
    } else if (riskScore >= 3) {
      severity = "MEDIUM";
      message = "API endpoint with multiple parameters discovered.";
    }

    results.push({
      type: "HIDDEN_API",
      severity: severity,
      endpoint: ep,
      message: message + (anomalies.length > 0 ? ` [Anomalies: ${anomalies.join(', ')}]` : "")
    });
  }

  return results;
};

module.exports = { extractEndpoints };
