const puppeteer = require('puppeteer');
const { URL } = require('url');

/**
 * ELITE Smart Crawler Service
 * A pentester-grade reconnaissance engine for deep asset discovery.
 */
class CrawlerService {
    constructor(options = {}) {
        this.maxDepth = options.maxDepth || 2;
        this.maxPages = options.maxPages || 20;
        this.delay = options.delay || 300; // Rate limiting
        this.mode = options.mode || 'active'; // passive | active | aggressive
        this.visited = new Set();
        this.queue = [];
        this.results = {
            endpoints: [],
            forms: [],
            apis: [],
            assets: [],
            scripts: [],
            cookies: [],
            storage: { local: '{}', session: '{}' },
            stats: {
                totalDiscovered: 0,
                uniqueEndpoints: 0
            }
        };
        this.scanContext = {
            endpoints: [],
            forms: [],
            cookies: [],
            scripts: [],
            storage: { local: '{}', session: '{}' },
            headers: {},
            metadata: {}
        };
    }

    async crawl(targetUrl) {
        console.log(`[Crawler] Starting ELITE discovery in ${this.mode} mode for: ${targetUrl}`);
        const domain = new URL(targetUrl).hostname;
        this.queue.push({ url: targetUrl, depth: 0 });

        const browser = await puppeteer.launch({
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });

        try {
            const page = await browser.newPage();
            
            // 1. Session Handling & Request Interception
            await page.setRequestInterception(true);
            page.on('request', (req) => {
                const url = req.url();
                const method = req.method();
                const headers = req.headers();
                const resourceType = req.resourceType();

                // Capture XHR, Fetch, and other API-like requests
                if (['xhr', 'fetch', 'script', 'websocket'].includes(resourceType)) {
                    this.addEndpoint({
                        url,
                        method,
                        source: resourceType,
                        headers,
                        type: this.classifyEndpoint(url),
                        params: this.extractParams(url, req.postData())
                    });
                }
                req.continue();
            });

            // Capture script contents via response interception
            page.on('response', async (res) => {
                const url = res.url();
                const resourceType = res.request().resourceType();
                
                if (resourceType === 'script' && res.status() === 200) {
                    try {
                        const content = await res.text();
                        if (content) {
                            this.results.scripts.push({
                                src: url,
                                content: content
                            });
                        }
                    } catch (e) {
                        // Response body might be empty or unavailable
                    }
                }
            });

            // 2. SPA Route Monitoring
            await page.exposeFunction('onRouteChanged', (newUrl) => {
                if (newUrl.includes(domain)) {
                    this.addLink(newUrl, 1); // Depth 1 for dynamic routes
                }
            });

            await page.evaluateOnNewDocument(() => {
                const pushState = history.pushState;
                history.pushState = function() {
                    pushState.apply(history, arguments);
                    window.onRouteChanged(window.location.href);
                };
                window.addEventListener('popstate', () => {
                    window.onRouteChanged(window.location.href);
                });
            });

            // 3. Main Crawl Loop
            while (this.queue.length > 0 && this.visited.size < this.maxPages) {
                const { url, depth } = this.queue.shift();
                if (this.visited.has(url) || depth > this.maxDepth) continue;

                this.visited.add(url);
                console.log(`[Crawler] (${this.visited.size}/${this.maxPages}) Crawling: ${url} (Depth: ${depth})`);

                try {
                    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(err => {
                        console.log(`[Crawler] Navigation bounded/timeout on ${url}, but proceeding with extraction...`);
                    });
                    await this.wait(this.delay + 2000);

                    // 4. Extract Static Assets
                    const pageResults = await page.evaluate(() => {
                        const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
                        const forms = Array.from(document.querySelectorAll('form')).map(f => ({
                            action: f.getAttribute('action') || window.location.href,
                            method: f.getAttribute('method')?.toUpperCase() || 'GET',
                            inputs: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                                name: i.getAttribute('name'),
                                type: i.getAttribute('type') || 'text'
                            }))
                        }));
                        return { links, forms };
                    });

                    // Add links to queue
                    pageResults.links.forEach(link => {
                        if (link.includes(domain)) {
                            this.addLink(link, depth + 1);
                        }
                    });

                    // Add forms to results
                    pageResults.forms.forEach(form => {
                        this.addForm(form, url);
                    });

                    // Capture Scripts and State
                    const cookies = await page.cookies();
                    this.results.cookies = [...new Set([...this.results.cookies, ...cookies])];
                    
                    const state = await page.evaluate(() => ({
                        scripts: Array.from(document.querySelectorAll('script')).map(s => ({
                            src: s.src || null,
                            content: s.src ? null : s.innerText
                        })),
                        storage: {
                            local: (() => { try { return JSON.stringify(window.localStorage) } catch(e){return "{}"} })(),
                            session: (() => { try { return JSON.stringify(window.sessionStorage) } catch(e){return "{}"} })()
                        }
                    }));
                    this.results.scripts = [...this.results.scripts, ...state.scripts];
                    this.results.storage = state.storage;

                    // 5. Active Interactions (if mode is active or aggressive)
                    if (this.mode !== 'passive') {
                        await this.performSmartInteractions(page);
                    }

                } catch (err) {
                    console.error(`[Crawler] Error crawling ${url}:`, err.message);
                }
            }

            // 6. Final Normalization
            this.finalizeScanContext(targetUrl);
            return this.scanContext;

        } finally {
            await browser.close();
        }
    }

    addLink(link, depth) {
        const cleaned = link.split('#')[0].split('?')[0]; // Simple normalization
        if (!this.visited.has(cleaned) && !this.queue.some(q => q.url === cleaned)) {
            this.queue.push({ url: cleaned, depth });
        }
    }

    addEndpoint(endpoint) {
        const key = `${endpoint.method}:${endpoint.url.split('?')[0]}`;
        if (!this.results.apis.some(a => `${a.method}:${a.url.split('?')[0]}` === key)) {
            this.results.apis.push({
                ...endpoint,
                priority: this.calculatePriority(endpoint),
                confidence: 0.9
            });
            this.results.stats.totalDiscovered++;
        }
    }

    addForm(form, sourceUrl) {
        const actionUrl = new URL(form.action, sourceUrl).href;
        this.results.forms.push({
            url: actionUrl,
            method: form.method,
            params: form.inputs.filter(i => i.name).map(i => i.name),
            source: 'form',
            type: this.classifyEndpoint(actionUrl)
        });
        this.results.stats.totalDiscovered++;
    }

    classifyEndpoint(url) {
        const lowercaseUrl = url.toLowerCase();
        if (lowercaseUrl.includes('admin')) return 'admin';
        if (lowercaseUrl.includes('login') || lowercaseUrl.includes('auth')) return 'auth';
        if (lowercaseUrl.includes('api')) return 'api';
        if (['.js', '.css', '.png', '.jpg', '.svg'].some(ext => lowercaseUrl.endsWith(ext))) return 'static';
        return 'general';
    }

    extractParams(url, postData) {
        const params = [];
        try {
            const urlObj = new URL(url);
            urlObj.searchParams.forEach((_, key) => params.push(key));
            
            if (postData) {
                try {
                    const json = JSON.parse(postData);
                    Object.keys(json).forEach(key => params.push(key));
                } catch {
                    const searchParams = new URLSearchParams(postData);
                    searchParams.forEach((_, key) => params.push(key));
                }
            }
        } catch (e) {}
        return [...new Set(params)];
    }

    calculatePriority(endpoint) {
        const typePriorities = { 'admin': 'high', 'auth': 'high', 'api': 'medium', 'general': 'low', 'static': 'low' };
        return typePriorities[endpoint.type] || 'low';
    }

    async performSmartInteractions(page) {
        try {
            // Find clickable elements that don't look like logout or delete
            const buttons = await page.$$('button, input[type="submit"], [role="button"]');
            for (const button of buttons.slice(0, 5)) { // Limit interactions
                const text = await page.evaluate(el => el.innerText.toLowerCase(), button).catch(() => '');
                if (['login', 'submit', 'search', 'filter', 'go', 'send'].some(k => text.includes(k))) {
                    console.log(`[Crawler] Strategically clicking: ${text}`);
                    await button.click().catch(() => {});
                    await this.wait(1000); // Wait for potential dynamic load
                }
            }
        } catch (e) {}
    }

    finalizeScanContext(targetUrl) {
        this.scanContext = {
            endpoints: [
                ...this.results.apis,
                ...this.results.forms
            ],
            cookies: this.results.cookies,
            scripts: this.results.scripts,
            storage: this.results.storage,
            metadata: {
                target: targetUrl,
                totalDiscovered: this.results.stats.totalDiscovered,
                pagesVisited: this.visited.size,
                scanMode: this.mode
            }
        };
        // Deduplicate endpoints by URL + Method + static Classification
        const seen = new Set();
        this.scanContext.endpoints = this.scanContext.endpoints.filter(e => {
            const key = `${e.method}:${e.url.split('?')[0]}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
        this.scanContext.stats = {
            uniqueEndpoints: this.scanContext.endpoints.length
        };
    }

    wait(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
}

module.exports = { CrawlerService };
