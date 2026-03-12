const puppeteer = require('puppeteer');
const techScanner = require('./technologyScanner');
const headerScanner = require('./headerScanner');
const dnsScanner = require('./dnsScanner');
const hostingDetector = require('./hostingDetector');
const vulnerabilityScanner = require('./vulnerabilityScanner');
const cookieScanner = require('./cookieScanner');
const sslScanner = require('./sslScanner');
const { issueExplanations } = require('./utils/securityExplainer');
const scriptScanner = require('./scanners/scriptScanner');
const { generateSummary } = require('./utils/reportSummary');
const axios = require('axios');
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

        // 1. Static signals + SSL check
        const [staticRes, dnsInfo, sslInfo] = await Promise.all([
            axios.get(url, {
                timeout: 10000,
                validateStatus: null,
                headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' }
            }),
            dnsScanner.scan(domain),
            sslScanner.scan(url)
        ]);

        const staticHeaders = staticRes.headers;
        const staticHtml = staticRes.data;

        // 2. Dynamic signals
        browser = await puppeteer.launch({
            headless: 'new',
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });
        const page = await browser.newPage();
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

        await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });

        const pageData = await page.evaluate((probeList) => {
            const data = {
                html: document.documentElement.innerHTML,
                meta: {},
                scripts: Array.from(document.querySelectorAll('script')).map(s => ({
                    src: s.src || null,
                    content: s.src ? null : s.innerText
                })),
                links: Array.from(document.querySelectorAll('link[href]')).map(l => l.href),
                jsVariables: {}
            };

            // Extract Meta Tags
            Array.from(document.querySelectorAll('meta')).forEach(m => {
                const name = m.getAttribute('name') || m.getAttribute('property');
                const content = m.getAttribute('content');
                if (name && content) data.meta[name.toLowerCase()] = content;
            });

            // Deep probe for JS variables
            probeList.forEach(path => {
                try {
                    const parts = path.split('.');
                    let current = window;
                    for (const part of parts) {
                        if (current[part] === undefined) {
                            current = undefined;
                            break;
                        }
                        current = current[part];
                    }

                    if (current !== undefined && current !== null) {
                        if (typeof current === 'string' || typeof current === 'number' || typeof current === 'boolean') {
                            data.jsVariables[path] = String(current);
                        } else {
                            data.jsVariables[path] = current.version || current.VERSION || (current.fn && current.fn.jquery) || 'exists';
                        }
                    }
                } catch (e) { }
            });

            return data;
        }, PROBE_LIST);

        const cookies = await page.cookies();
        await browser.close();
        browser = null;

        // 3. Execution Phase
        const scanData = {
            html: pageData.html || staticHtml,
            headers: staticHeaders,
            scripts: pageData.scripts,
            links: pageData.links,
            cookies: cookies,
            jsVariables: pageData.jsVariables,
            url,
            meta: pageData.meta
        };

        const detectedTechnologies = await techScanner.scan(scanData);
        const hostingProvider = await hostingDetector.detect(dnsInfo, staticHeaders);

        // 4. Security vulnerability and headers
        const [vulnerabilities, securityHeaders, rawCookieSecurity, suspiciousScripts] = await Promise.all([
            vulnerabilityScanner.scanAll(detectedTechnologies),
            headerScanner.scan(url),
            cookieScanner.analyze(cookies),
            scriptScanner.analyze(pageData.scripts)
        ]);

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
        const processedScripts = suspiciousScripts.map(script => ({
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

        const scanDuration = ((Date.now() - startTime) / 1000).toFixed(2);

        const results = {
            url,
            target: domain,
            timestamp: new Date().toISOString(),
            scanDuration: `${scanDuration}s`,
            technologies: detectedTechnologies,
            securityHeaders,
            dnsInfo,
            hostingProvider,
            vulnerabilities,
            sslInfo,
            cookieSecurity,
            suspiciousScripts: processedScripts
        };

        // Generate Human-Readable Summary
        results.summary = generateSummary(results);

        return results;

    } catch (err) {
        if (browser) await browser.close();
        console.error('[Engine Error]:', err.message);
        throw err;
    }
}

module.exports = { run };
