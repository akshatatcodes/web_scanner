const axios = require('axios');
const cheerio = require('cheerio');
const puppeteer = require('puppeteer');
const rules = require('./rules');

/**
 * Technology Detection Module
 */
async function scan(url) {
    let browser = null;
    try {
        console.log(`[TechDetector] Fetching static content for: ${url}`);
        const response = await axios.get(url, {
            timeout: 10000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            },
            validateStatus: null
        });

        const headers = response.headers;
        const html = response.data;

        console.log('[TechDetector] Launching browser...');
        browser = await puppeteer.launch({
            headless: 'new',
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });
        const page = await browser.newPage();
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

        console.log('[TechDetector] Navigating to page...');
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });

        // Collect unique variables to probe to avoid serialization issues with entire tech objects
        const varsToProbe = new Set();
        Object.values(rules.technologies).forEach(tech => {
            if (tech.js) tech.js.forEach(v => varsToProbe.add(v));
        });

        console.log('[TechDetector] Probing JS variables...');
        const jsVariables = await page.evaluate((vars) => {
            const results = {};
            vars.forEach(varName => {
                try {
                    const parts = varName.split('.');
                    let current = window;
                    for (const part of parts) {
                        if (current[part] === undefined) {
                            current = undefined;
                            break;
                        }
                        current = current[part];
                    }
                    if (current !== undefined) results[varName] = true;
                } catch (e) { }
            });
            return results;
        }, Array.from(varsToProbe));

        const renderedHtml = await page.content();
        const scripts = await page.evaluate(() =>
            Array.from(document.querySelectorAll('script[src]')).map(s => s.src)
        );

        await browser.close();
        browser = null;

        console.log('[TechDetector] Matching rules...');
        const detected = [];
        for (const [name, tech] of Object.entries(rules.technologies)) {
            let isMatch = false;

            // Match Headers (Case Insensitive)
            if (tech.headers) {
                for (const [hdr, pattern] of Object.entries(tech.headers)) {
                    const value = headers[hdr.toLowerCase()];
                    if (value && pattern.test(Array.isArray(value) ? value.join(' ') : value)) {
                        isMatch = true;
                        break;
                    }
                }
            }

            // Match HTML
            if (!isMatch && tech.html) {
                for (const pattern of tech.html) {
                    if (pattern.test(html) || pattern.test(renderedHtml)) {
                        isMatch = true;
                        break;
                    }
                }
            }

            // Match Scripts
            if (!isMatch && tech.script) {
                const scriptPatterns = Array.isArray(tech.script) ? tech.script : [tech.script];
                for (const pattern of scriptPatterns) {
                    if (scripts.some(s => pattern.test(s))) {
                        isMatch = true;
                        break;
                    }
                }
            }

            // Match JS Variables
            if (!isMatch && tech.js) {
                for (const varName of tech.js) {
                    if (jsVariables[varName]) {
                        isMatch = true;
                        break;
                    }
                }
            }

            if (isMatch) {
                detected.push({
                    name,
                    categories: tech.cats.map(id => rules.categories[id]?.name || 'Unknown')
                });
            }
        }

        return detected;

    } catch (error) {
        if (browser) await browser.close();
        console.error('[TechDetector Error]:', error.message);
        return [];
    }
}

module.exports = { scan };
