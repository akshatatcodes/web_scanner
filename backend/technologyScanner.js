const technologies = require('./rules/technologies');
const categories = require('./rules/categories');
const cheerio = require('cheerio');

/**
 * Professional High-Performance Wappalyzer Engine
 */
class TechDetector {
    constructor() {
        this.technologies = technologies;
        this.categories = categories;
    }

    analyze(data) {
        const detected = [];
        const { html, headers, scripts, cookies, jsVariables, url, meta, links } = data;
        const $ = cheerio.load(html || '');

        const normalizedHeaders = {};
        if (headers) {
            Object.keys(headers).forEach(k => {
                normalizedHeaders[k.toLowerCase()] = headers[k];
            });
        }

        for (const [name, tech] of Object.entries(this.technologies)) {
            let isMatch = false;
            let currentVersion = null;

            // Helper for matching and version extraction
            const check = (pattern, target) => {
                if (target === undefined || target === null) return false;
                const targetStr = String(target);
                const pts = Array.isArray(pattern) ? pattern : [pattern];
                let matched = false;

                for (const p of pts) {
                    // Split version pattern if present
                    const parts = p.split('\\;version:');
                    const regexStr = parts[0];
                    const versionPattern = parts[1];

                    try {
                        const regex = new RegExp(regexStr, 'i');
                        const match = targetStr.match(regex);
                        if (match) {
                            matched = true;
                            if (versionPattern && !currentVersion) {
                                currentVersion = versionPattern.replace(/\\(\d+)/g, (_, group) => match[group] || '');
                            }
                        }
                    } catch (e) { }
                }
                return matched;
            };

            // Exhaustive check across all signals to find version if possible

            // 1. Headers
            if (tech.headers) {
                for (let [hName, pattern] of Object.entries(tech.headers)) {
                    if (check(pattern, normalizedHeaders[hName.toLowerCase()])) isMatch = true;
                }
            }

            // 2. HTML
            if (tech.html) {
                if (check(tech.html, html)) isMatch = true;
            }

            // 3. Scripts
            const scriptPatterns = tech.script || tech.scriptSrc;
            if (scriptPatterns) {
                if (check(scriptPatterns, scripts.join(' '))) isMatch = true;
            }

            // 4. DOM
            if (tech.dom) {
                const domRules = Array.isArray(tech.dom) ? tech.dom : [tech.dom];
                for (const rule of domRules) {
                    try {
                        const selector = typeof rule === 'string' ? rule : rule.selector;
                        const el = $(selector);
                        if (el.length > 0) {
                            if (typeof rule === 'object' && rule.attributes) {
                                for (const [attr, attrPattern] of Object.entries(rule.attributes)) {
                                    if (check(attrPattern, el.attr(attr))) isMatch = true;
                                }
                            } else {
                                isMatch = true;
                            }
                        }
                    } catch (e) { }
                }
            }

            // 5. Meta
            if (tech.meta) {
                for (const [mName, pattern] of Object.entries(tech.meta)) {
                    if (check(pattern, meta[mName.toLowerCase()])) isMatch = true;
                }
            }

            // 6. JS
            if (tech.js) {
                for (const [vName, pattern] of Object.entries(tech.js)) {
                    if (jsVariables[vName] !== undefined && jsVariables[vName] !== null) {
                        if (pattern === '' || check(pattern, jsVariables[vName])) isMatch = true;
                    }
                }
            }

            // 7. Cookies
            if (tech.cookies) {
                for (const [cName, pattern] of Object.entries(tech.cookies)) {
                    // Support regex for cookie names too!
                    const cookie = cookies.find(c => {
                        try { return new RegExp(cName.replace('*', '.*'), 'i').test(c.name); }
                        catch (e) { return c.name === cName; }
                    });
                    if (cookie && (pattern === '' || check(pattern, cookie.value))) isMatch = true;
                }
            }

            // 8. URL
            if (tech.url) {
                if (check(tech.url, url)) isMatch = true;
            }

            // 9. CSS
            if (tech.css) {
                if (check(tech.css, links.join(' '))) isMatch = true;
            }

            if (isMatch) {
                detected.push({
                    name,
                    version: currentVersion || undefined,
                    icon: tech.icon,
                    categories: tech.cats.map(id => this.categories[id]?.name || 'Misc')
                });
            }
        }

        return detected;
    }
}

const detector = new TechDetector();

async function scan(pageData) {
    return detector.analyze(pageData);
}

module.exports = { scan };
