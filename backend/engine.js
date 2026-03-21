require('dotenv').config();
const puppeteer = require('puppeteer');
const techScanner = require('./technologyScanner');
const headerScanner = require('./headerScanner');
const dnsScanner = require('./dnsScanner');
const hostingDetector = require('./hostingDetector');
const vulnerabilityScanner = require('./vulnerabilityScanner');
const cookieScanner = require('./cookieScanner');
const sslScanner = require('./sslScanner');
const { issueExplanations } = require('./utils/securityExplainer');
const domainReputationScanner = require('./scanners/domainReputationScanner');
const subdomainScanner = require('./scanners/subdomainScanner');
const scriptScanner = require('./scanners/scriptScanner');
const { classifySubdomain } = require('./recon/subdomainIntel');
const { checkTakeover } = require('./recon/takeoverEngine');
const { extractWaybackData } = require('./recon/waybackAnalyzer');
const { calculateScore } = require('./recon/attackSurfaceScorer');
const { pLimit } = require('./recon/utils');
const { scanAdminPanels } = require('./scanners/adminScanner');
const { extractEndpoints } = require('./scanners/endpointScanner');
const { scanSecrets } = require('./scanners/secretScanner');
const { scanDirectories } = require('./scanners/directoryScanner');
const { scanCORS } = require('./scanners/corsScanner');
const { scanGraphQL } = require('./scanners/graphqlScanner');
const { scanOpenRedirect } = require('./scanners/openRedirectScanner');
const { scanSSRF } = require('./scanners/ssrfScanner');
const { scanAuthBypass } = require('./scanners/authBypassScanner');
const { scanRateLimit } = require('./scanners/rateLimitScanner');
const { scanSQLi } = require('./scanners/sqlInjectionScanner');
const { scanCommandInjection } = require('./scanners/commandInjectionScanner');
const { scanIDOR } = require('./scanners/idorScanner');
const { scanJWT } = require('./scanners/jwtScanner');
const { generateSummary } = require('./utils/reportSummary');
const { CrawlerService } = require('./services/crawlerService');
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');
const technologies = require('./rules/technologies');

// Pre-calculate ALL unique JS property paths to probe
const JS_PATHS_TO_PROBE = new Set();
Object.values(technologies).forEach(t => {
    if (t.js) Object.keys(t.js).forEach(v => JS_PATHS_TO_PROBE.add(v));
});
const PROBE_LIST = Array.from(JS_PATHS_TO_PROBE);

/**
 * Professional Multi-Layer Scanning Engine
 */
async function run(url) {
    const startTime = Date.now();
    console.log(`[Engine] Starting deep analysis (with versions) for: ${url}`);

    let browser = null;
    try {
        const domain = new URL(url).hostname;

        // 1. Phase 1: Surface Discovery & Infrastructure Analysis
        console.log(`[Engine] Phase 1 - Surface Discovery & Infrastructure Analysis: ${url}`);
        const [staticRes, dnsInfo, sslInfo] = await Promise.all([
            axios.get(url, {
                timeout: 30000,
                validateStatus: null,
                headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' }
            }),
            dnsScanner.scan(domain),
            sslScanner.scan(url)
        ]);

        const staticHeaders = staticRes.headers;
        const staticHtml = staticRes.data;

        // 1.5 Phase 1.5: WAF Profiling & Infrastructure Intelligence
        console.log(`[Engine] Phase 1.5 - WAF Profiling & Infrastructure Intelligence...`);
        const { detectWaf } = require('./scanners/wafScanner');
        const wafResults = await detectWaf(url);
        
        // Determine initial evasion strategy
        if (wafResults.detected) {
            wafResults.evasionStrategy = 'url_encode'; // Default safe strategy
            if (wafResults.name === 'Cloudflare' || wafResults.confidence > 0.8) {
                wafResults.evasionStrategy = 'double_encode'; // More aggressive for known tough WAFs
            }
        }

        // Phase 2: Fast Static Extraction (cheerio-based, no Puppeteer)
        console.log(`[Engine] Phase 2 - Fast Static Extraction (Puppeteer crawl available on-demand)...`);
        const scanContext = buildStaticScanContext(url, staticHtml, staticHeaders);
        scanContext.waf = wafResults;
        
        // 3. Phase 3: Technology Fingerprinting & Security Pattern Analysis
        console.log(`[Engine] Phase 3 - Technology Fingerprinting & Security Pattern Analysis...`);
        
        // Prepare data for tech scanner from static HTML results
        // Use scripts from static context; provide safe defaults for meta/links/jsVariables
        const $ = require('cheerio').load(typeof staticHtml === 'string' ? staticHtml : '');
        const metaTags = {};
        $('meta[name]').each((_, el) => {
            metaTags[$(el).attr('name').toLowerCase()] = $(el).attr('content') || '';
        });
        const linkHrefs = $('link[href]').map((_, el) => $(el).attr('href')).get();

        const scanData = {
            html: staticHtml,
            headers: staticHeaders,
            scripts: scanContext.scripts, // All script tags from static extraction
            cookies: scanContext.cookies,
            url,
            meta: metaTags,
            links: linkHrefs,
            jsVariables: {}, // No runtime JS probing in static mode
            scanContext
        };
        const detectedTechnologies = await techScanner.scan(scanData);
        const hostingProvider = await hostingDetector.detect(dnsInfo, staticHeaders);

        // Safe execution wrapper to prevent hangs/crashes in sub-scanners
        const safeRun = async (scannerFn, ...args) => {
            try {
                return await scannerFn(...args) || [];
            } catch (err) {
                console.error(`[Engine] Scanner Error in ${scannerFn.name}:`, err.message);
                return [];
            }
        };

        // 4. Phase 4: Security Vulnerability and Headers
        console.log(`[Engine] Phase 4 - Multi-Vector Vulnerability Discovery & Header Analysis...`);
        const [vulnerabilities, securityHeaders, rawCookieSecurity, rawSuspiciousScripts] = await Promise.all([
            vulnerabilityScanner.scanAll(detectedTechnologies),
            headerScanner.scan(url),
            cookieScanner.analyze(scanContext.cookies),
            scriptScanner.analyze(scanContext.scripts)
        ]);
        
        console.log(`[Engine] Core vulnerability scans complete. Technologies with CVEs: ${Object.keys(vulnerabilities).length}`);

        // Specialized scanners that benefit from deep crawling context
        const scriptUrls = scanContext.scripts.filter(s => s.src).map(s => s.src);
        const [secretLeaks, corsIssues, graphqlFindings, openRedirects, ssrfFindings, adminPanels, hiddenEndpoints, directories] = await Promise.all([
            safeRun(scanSecrets, staticHtml), 
            safeRun(scanCORS, url, staticHeaders),
            safeRun(scanGraphQL, url),
            safeRun(scanOpenRedirect, url),
            safeRun(scanSSRF, url),
            safeRun(scanAdminPanels, url),
            safeRun(extractEndpoints, url, scriptUrls),
            safeRun(scanDirectories, url)
        ]);

        console.log(`[Engine] Discovery Complete. Unique Endpoints Found: ${scanContext.stats.uniqueEndpoints}`);

        // 5. Phase 5: Authorization Bypass & Resilience Testing
        console.log(`[Engine] Phase 5 - Authorization Bypass & Resilience Testing...`);
        const discoveredPaths = scanContext.endpoints.map(e => {
            try { return new URL(e.url).pathname } catch { return e.url }
        });

        const [authBypasses, rateLimits] = await Promise.all([
            safeRun(scanAuthBypass, url, discoveredPaths),
            safeRun(scanRateLimit, url)
        ]);

        // 6. Phase 6 & 7: Exploitation Intelligence & Behavior-Based Detection
        console.log(`[Engine] Phase 6 & 7 - Exploitation Intelligence & Behavior-Based Detection...`);
        const discoveredURLs = scanContext.endpoints.map(e => e.url);
        const { runBehaviorAnalysis } = require('./scanners/behavior/behaviorAnalyzer');

        const [sqli, cmdInjection, idors, jwtIssues, behaviorAnomalies] = await Promise.all([
            safeRun(scanSQLi, discoveredURLs, scanContext),
            safeRun(scanCommandInjection, discoveredURLs, scanContext),
            safeRun(scanIDOR, discoveredURLs, scanContext),
            safeRun(scanJWT, {
                cookies: scanContext.cookies,
                local: scanContext.storage.local,
                session: scanContext.storage.session
            }),
            safeRun(runBehaviorAnalysis, discoveredURLs)
        ]);
        console.log(`[Engine] Phase 6 & 7 complete. Target Endpoints Scanned: ${discoveredURLs.length}`);

        // URL Normalization for reputation check
        const normalizedUrl = new URL(url).origin;

        // 5. Advanced OSINT & Infrastructure (Reputation, Subdomains)
        const [reputationResult, subdomainList] = await Promise.all([
            domainReputationScanner.scan(normalizedUrl),
            subdomainScanner.scan(domain)
        ]);

        // Phase 6A - Core Recon Layer (Hacker Heuristics)
        console.log(`[Engine] Phase 6A - Core Recon Layer (Subdomain Intel, Takeovers, Wayback)...`);
        const limit = pLimit(10); // Safe limit for DNS/HTTP takeover checks
        const takeoverResults = await Promise.all(
            subdomainList.map(sub => limit(() => checkTakeover(sub)))
        );
        const validTakeovers = takeoverResults.filter(Boolean);
        
        const waybackData = await extractWaybackData(domain);
        
        const subdomainIntelMap = {};
        let highestSubdomainRisk = "low";
        
        for (const sub of subdomainList) {
            const r = classifySubdomain(sub);
            subdomainIntelMap[sub] = { type: r, risk: r };
            if (r === 'critical') highestSubdomainRisk = 'critical';
            if (r === 'high' && highestSubdomainRisk !== 'critical') highestSubdomainRisk = 'high';
        }

        // Phase 6B - Infrastructure Exploitation Layer
        console.log(`[Engine] Phase 6B - Infrastructure Layer (ASN Pivoting, CDN Bypass)...`);
        const { parseAsn } = require('./recon/asnPivot');
        const { checkCdnBypass } = require('./recon/cdnBypass');
        
        const asnData = await parseAsn(domain);
        let cdnBypassData = null;
        if (asnData && asnData.isCloud) {
             console.log(`[Engine] Target is behind Cloud/CDN (${asnData.organization}). Attempting Bypass...`);
             cdnBypassData = await checkCdnBypass(domain, asnData.ip, subdomainList, true);
        }

        // Phase 6C - Deep Leak & Intelligence Mining
        console.log(`[Engine] Phase 6C - Intelligence Mining (JS Analyzer, GitHub Leaks)...`);
        const { analyzeJS } = require('./recon/jsAnalyzer');
        const { searchGithubLeaks } = require('./recon/githubLeaks');
        const [jsReconData, githubReconData] = await Promise.all([
             analyzeJS(scanContext.scripts.slice(0, 15)), // Limit to 15 scripts to avoid massive slowdown
             searchGithubLeaks(domain)
        ]);

        const reconRiskScore = calculateScore({
            subdomainRisk: highestSubdomainRisk,
            takeover: validTakeovers.length > 0 ? validTakeovers[0] : null,
            waybackData,
            asn: asnData,
            cdnBypass: cdnBypassData,
            jsData: jsReconData,
            githubData: githubReconData,
            behaviorAnomalies: behaviorAnomalies ? behaviorAnomalies.anomalies : []
        });

        const domainIntel = {
            reputation: reputationResult,
            subdomains: subdomainList,
            subdomainIntel: subdomainIntelMap,
            takeovers: validTakeovers,
            wayback: waybackData,
            asn: asnData,
            cdnBypass: cdnBypassData,
            jsRecon: jsReconData,
            githubRecon: githubReconData,
            reconScoring: reconRiskScore,
            dns: dnsInfo
        };

        // Add blacklist status as an XSS finding if listed
        if (reputationResult && reputationResult.status === 'malicious') {
            rawSuspiciousScripts.push({
                source: 'Google Safe Browsing',
                issues: reputationResult.threats.map(t => ({
                    type: 'Malicious Content Detected',
                    code: 'BLACKLISTED',
                    reason: `Domain is listed for ${t.type.toLowerCase().replace('_', ' ')} on ${t.platform.toLowerCase().replace('_', ' ')}.`,
                    riskScore: 3
                })),
                risk: 'HIGH',
                riskScore: 3
            });
        }

        // Logic for XSS Risk Level
        const hasCSP = Object.keys(staticHeaders).some(h => h.toLowerCase() === 'content-security-policy');
        const scriptIssues = rawSuspiciousScripts.flatMap(s => s.issues);
        const hasDangerousJS = scriptIssues.length > 0;

        let xssRiskLevel = 'LOW';
        if (hasDangerousJS && !hasCSP) {
            xssRiskLevel = 'HIGH';
        } else if (hasDangerousJS) {
            xssRiskLevel = 'MEDIUM';
        } else if (!hasCSP) {
            xssRiskLevel = 'LOW';
        }

        // Add XSS Risk finding if CSP is missing
        if (!hasCSP) {
            rawSuspiciousScripts.push({
                source: 'HTTP Headers',
                issues: [{
                    type: 'Missing Security Protection',
                    code: 'MISSING_CSP',
                    reason: 'Content Security Policy (CSP) header is not enabled.',
                    riskScore: hasDangerousJS ? 3 : 1
                }],
                risk: hasDangerousJS ? 'HIGH' : 'LOW',
                riskScore: hasDangerousJS ? 3 : 1
            });
        }

        // Attach human explanations to cookie issues
        const cookieSecurity = rawCookieSecurity.map(cookie => ({
            ...cookie,
            humanIssues: cookie.issues.map(issue => ({
                ...issue,
                details: issueExplanations[issue.code] || {
                    title: "Unknown Security Issue",
                    explanation: "An undocumented security issue was detected.",
                    impact: "The exact impact of this issue is currently unknown.",
                    recommendation: "Review the technical details and follow general security best practices."
                }
            }))
        }));

        // Attach human explanations to script issues
        const processedScripts = rawSuspiciousScripts.map(script => ({
            ...script,
            humanIssues: script.issues.map(issue => ({
                ...issue,
                details: issueExplanations[issue.code] || {
                    title: issue.type,
                    explanation: issue.reason,
                    impact: "Potentially malicious code execution in the user's browser.",
                    recommendation: "Only load scripts from trusted providers and avoid risky inline practices."
                }
            }))
        }));

        const results = {
            url,
            target: domain,
            timestamp: new Date().toISOString(),
            technologies: detectedTechnologies,
            securityHeaders,
            dnsInfo,
            hostingProvider,
            vulnerabilities,
            sslInfo,
            cookieSecurity,
            suspiciousScripts: processedScripts,
            domainIntel,
            adminPanels,
            hiddenEndpoints,
            secretLeaks,
            directories,
            corsIssues,
            graphqlFindings,
            openRedirects,
            ssrfFindings,
            authBypasses,
            rateLimits,
            sqli,
            cmdInjection,
            idors,
            jwtIssues,
            scanContext,
            waf: wafResults
        };

        // 6. PRO Attack Graph Engine - Normalization & Analysis
        const findings = [];
        
        // Normalize Behavior Anomalies (Phase 7)
        if (behaviorAnomalies && behaviorAnomalies.anomalies && behaviorAnomalies.anomalies.length > 0) {
            behaviorAnomalies.anomalies.forEach(anom => {
                findings.push({ 
                    type: 'behavioral_anomaly', 
                    severity: anom.confidence === 'CRITICAL' ? 'CRITICAL' : (anom.confidence === 'HIGH' ? 'HIGH' : 'MEDIUM'), 
                    evidence: `Behavioral engine confirmed ${anom.vulnerability} at ${new URL(anom.endpoint).pathname} (Confidence: ${anom.confidence})` 
                });
            });
        }
        
        // Provide raw stats to frontend regardless of vulns
        results.behaviorProfiling = behaviorAnomalies || { endpointsProfiled: 0, payloadsSent: 0, anomalies: [] };

        // Normalize SSRF
        if (ssrfFindings && ssrfFindings.length > 0) {
            findings.push({ 
                type: 'ssrf', 
                severity: 'HIGH', 
                evidence: `Found ${ssrfFindings.length} vulnerable endpoints allowing internal requests.` 
            });
        }

        // Normalize Internal Ports (via DNS or Port Scan)
        const hasInternalPort = (dnsInfo.issues && dnsInfo.issues.some(i => i.code === 'INTERNAL_IP')) || 
                               (results.portScanner && results.portScanner.some(p => [22, 3306, 6379, 8080].includes(p.port)));
        if (hasInternalPort) {
            findings.push({ 
                type: 'internal_port_open', 
                severity: 'INFO', 
                evidence: "Internal infrastructure services detected (SSH/DB/Admin)." 
            });
        }

        // Normalize IDOR
        if (idors && idors.length > 0) {
            findings.push({ 
                type: 'idor', 
                severity: 'HIGH', 
                evidence: `Discovered IDs exposing private data at ${idors[0].url}` 
            });
        }

        // Normalize WAF Detection
        if (wafResults.detected) {
            findings.push({ 
                type: 'waf_detected', 
                severity: 'INFO', 
                evidence: `Target protected by ${wafResults.name} (Confidence: ${(wafResults.confidence * 100).toFixed(0)}%). Evasion active via ${wafResults.evasionStrategy}.` 
            });
        }

        // Normalize JWT
        if (jwtIssues && jwtIssues.length > 0) {
            findings.push({ 
                type: 'jwt_misconfig', 
                severity: 'MEDIUM', 
                evidence: "JWT found with weak signature or insecure algorithm." 
            });
        }

        // Normalize XSS Risks
        const hasXSSRisk = processedScripts.some(s => s.humanIssues.some(i => i.riskScore >= 2));
        if (hasXSSRisk) {
            findings.push({ 
                type: 'xss_risk', 
                severity: 'MEDIUM', 
                evidence: "Untrusted scripts or dangerous DOM sinks detected." 
            });
        }

        // Normalize Missing HttpOnly
        const hasMissingHttpOnly = cookieSecurity.some(c => c.humanIssues.some(i => i.code === 'MISSING_HTTPONLY'));
        if (hasMissingHttpOnly) {
            findings.push({ 
                type: 'missing_httponly', 
                severity: 'LOW', 
                evidence: "Session cookies detected without HttpOnly protection." 
            });
        }

        // Normalize SQLi
        if (sqli && sqli.length > 0) {
            findings.push({ 
                type: 'sqli', 
                severity: 'HIGH', 
                evidence: `Confirmed SQL injection points via time-based or error-based analysis.` 
            });
        }

        // Normalize Auth Bypass
        if (authBypasses && authBypasses.length > 0) {
            findings.push({ 
                type: 'auth_bypass', 
                severity: 'HIGH', 
                evidence: "Authentication mechanisms can be bypassed using discovered paths." 
            });
        }

        // Normalize Open Redirect
        if (openRedirects && openRedirects.length > 0) {
            findings.push({ 
                type: 'open_redirect', 
                severity: 'MEDIUM', 
                evidence: "Redirect parameters can be manipulated for phishing purposes." 
            });
        }

        // Normalize Missing CSP
        const hasCSPHeader = Object.keys(staticHeaders).some(h => h.toLowerCase() === 'content-security-policy');
        if (!hasCSPHeader) {
            findings.push({ 
                type: 'missing_csp', 
                severity: 'LOW', 
                evidence: "No Content Security Policy detected. Defense-in-depth is missing." 
            });
        }

        // Run Attack Graph Analysis
        const { analyzeAttackGraph } = require('./utils/attackGraph');
        results.attackChains = analyzeAttackGraph(findings);
        results.normalizedFindings = findings; 

        // Update Scan Duration
        results.scanDuration = `${((Date.now() - startTime) / 1000).toFixed(2)}s`;

        // Generate Human-Readable Summary
        results.summary = generateSummary(results);

        return results;

    } catch (err) {
        if (browser) await browser.close();
        console.error('[Engine Error]:', err.message);
        throw err;
    }
}

/**
 * Build a minimal scanContext from static HTML (cheerio), no Puppeteer needed.
 */
function buildStaticScanContext(url, html, headers) {
    const $ = cheerio.load(typeof html === 'string' ? html : '');
    const domain = new URL(url).hostname;

    const endpoints = [];
    const seen = new Set();

    // Extract links
    $('a[href]').each((_, el) => {
        try {
            const href = $(el).attr('href');
            const abs = new URL(href, url).href;
            const key = `GET:${abs.split('?')[0]}`;
            if (!seen.has(key)) {
                seen.add(key);
                endpoints.push({ url: abs, method: 'GET', source: 'link', type: 'general' });
            }
        } catch {}
    });

    // Extract form actions
    $('form').each((_, el) => {
        try {
            const action = $(el).attr('action') || url;
            const method = ($(el).attr('method') || 'GET').toUpperCase();
            const abs = new URL(action, url).href;
            const key = `${method}:${abs.split('?')[0]}`;
            if (!seen.has(key)) {
                seen.add(key);
                endpoints.push({ url: abs, method, source: 'form', type: 'general' });
            }
        } catch {}
    });

    const scripts = [];
    $('script').each((_, el) => {
        const src = $(el).attr('src');
        const content = !src ? $(el).html() : null;
        scripts.push({ src: src ? new URL(src, url).href : null, content });
    });

    const cookies = [];
    if (headers['set-cookie']) {
        const raw = Array.isArray(headers['set-cookie']) ? headers['set-cookie'] : [headers['set-cookie']];
        raw.forEach(c => {
            const parts = c.split(';');
            const [nameVal] = parts;
            const [name, value] = nameVal.split('=');
            cookies.push({
                name: (name || '').trim(),
                value: (value || '').trim(),
                httpOnly: /httponly/i.test(c),
                secure: /secure/i.test(c),
                sameSite: (/samesite=(\w+)/i.exec(c) || [])[1] || 'None'
            });
        });
    }

    return {
        endpoints,
        cookies,
        scripts,
        forms: [],
        storage: { local: '{}', session: '{}' },
        headers,
        metadata: { target: url, scanMode: 'static', pagesVisited: 1 },
        stats: { uniqueEndpoints: endpoints.length }
    };
}

/**
 * Run the full Puppeteer-based deep crawl separately (on-demand).
 */
async function deepCrawl(url) {
    console.log(`[Engine] Starting on-demand deep crawl for: ${url}`);
    const crawler = new CrawlerService({ mode: 'active', maxPages: 15 });
    return await crawler.crawl(url);
}

module.exports = { run, deepCrawl };
