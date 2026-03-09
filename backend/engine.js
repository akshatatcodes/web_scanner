const puppeteer = require('puppeteer');
const techScanner = require('./technologyScanner');
const headerScanner = require('./headerScanner');
const dnsScanner = require('./dnsScanner');
const hostingDetector = require('./hostingDetector');
const vulnerabilityScanner = require('./vulnerabilityScanner');
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
    console.log(`[Engine] Starting deep analysis (with versions) for: ${url}`);

    let browser = null;
    try {
        const domain = new URL(url).hostname;

        // 1. Static signals
        const [staticRes, dnsInfo] = await Promise.all([
            axios.get(url, {
                timeout: 10000,
                validateStatus: null,
                headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' }
            }),
            dnsScanner.scan(domain)
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
                scripts: Array.from(document.querySelectorAll('script[src]')).map(s => s.src),
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
                        // Capture value for matching (limit string length)
                        if (typeof current === 'string' || typeof current === 'number' || typeof current === 'boolean') {
                            data.jsVariables[path] = String(current);
                        } else {
                            // If it's an object/function, we just mark it as existing
                            // unless it has a common version property we can snag
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
            cookies: cookies.map(c => ({ name: c.name, value: c.value })),
            jsVariables: pageData.jsVariables,
            url,
            meta: pageData.meta
        };

        const detectedTechnologies = await techScanner.scan(scanData);
        const hostingProvider = await hostingDetector.detect(dnsInfo, staticHeaders);

        // 4. Security Vulnerability Scan (NVD API)
        const vulnerabilities = await vulnerabilityScanner.scanAll(detectedTechnologies);

        return {
            url,
            timestamp: new Date().toISOString(),
            technologies: detectedTechnologies,
            securityHeaders: await headerScanner.scan(url),
            dnsInfo,
            hostingProvider,
            vulnerabilities
        };

    } catch (err) {
        if (browser) await browser.close();
        console.error('[Engine Error]:', err.message);
        throw err;
    }
}

module.exports = { run };
