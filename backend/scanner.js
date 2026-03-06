const { spawn } = require('child_process');
const path = require('path');
const axios = require('axios');
const cheerio = require('cheerio');
const puppeteer = require('puppeteer');

// ─── Python Analysis Bridge ─────────────────────────────────────────────────
function runPythonAnalysis(url) {
    return new Promise((resolve) => {
        const isWindows = process.platform === 'win32';
        const pythonExe = path.join(
            __dirname, 'python_engine', 'venv',
            isWindows ? 'Scripts' : 'bin', 'python'
        );
        const scriptPath = path.join(__dirname, 'python_engine', 'analyzer.py');
        const proc = spawn(pythonExe, [scriptPath, url]);
        let out = '';
        proc.stdout.on('data', d => { out += d.toString(); });
        proc.stderr.on('data', d => { console.error('[Python]', d.toString()); });
        proc.on('close', () => {
            try { resolve(JSON.parse(out)); }
            catch { resolve({ python_status: 'error' }); }
        });
    });
}

// ─── Main Scanner ────────────────────────────────────────────────────────────
async function scanUrl(url) {
    let browser = null;
    try {
        // ── Phase 1: Fast axios fetch for response headers & static HTML ─────────
        const axiosRes = await axios.get(url, {
            timeout: 12000,
            maxRedirects: 5,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
            },
            validateStatus: () => true
        });

        const httpStatus = axiosRes.status;
        const resHeaders = axiosRes.headers;
        const rawHtml = typeof axiosRes.data === 'string' ? axiosRes.data : JSON.stringify(axiosRes.data);
        const $ = cheerio.load(rawHtml);
        const serverHdr = (resHeaders['server'] || '').toLowerCase();
        const xPoweredBy = (resHeaders['x-powered-by'] || '').toLowerCase();
        const cookieHdr = (resHeaders['set-cookie'] || []).join(';').toLowerCase();
        const generatorMeta = ($('meta[name="generator"]').attr('content') || '').toLowerCase();

        // ── Phase 2: Python analysis (background) ────────────────────────────────
        const pythonPromise = runPythonAnalysis(url);

        // ── Phase 3: Puppeteer – headless browser for JS-based detections ─────────
        browser = await puppeteer.launch({
            headless: 'new',
            args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--disable-dev-shm-usage']
        });
        const page = await browser.newPage();
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');

        // Use domcontentloaded so we don't wait for every lazy-loaded asset
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
        // Give scripts 2 more seconds to execute
        await new Promise(r => setTimeout(r, 2000));

        // Evaluate all JS-based fingerprints inside the browser context
        const jsFingerprints = await page.evaluate(() => {
            const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
            const links = Array.from(document.querySelectorAll('link[href]')).map(l => l.href);
            const all = scripts.concat(links).join(' ');
            const pageHtml = document.documentElement.outerHTML;

            return {
                // Frameworks
                react: !!window.React || !!window.ReactDOM
                    || !!document.querySelector('[data-reactroot],[data-reactid]')
                    || pageHtml.includes('__reactFiber') || all.includes('react'),
                vue: !!window.Vue || !!window.__VUE__
                    || !!document.querySelector('[data-v-][id="__nuxt"]')
                    || all.includes('vue'),
                angular: !!window.angular || !!window.ng
                    || !!document.querySelector('[ng-version],[ng-app]')
                    || all.includes('angular'),
                svelte: !!document.querySelector('[class*="svelte-"]') || pageHtml.includes('__svelte'),
                nextjs: !!document.getElementById('__NEXT_DATA__') || !!window.__NEXT_DATA__,
                nuxt: !!document.getElementById('__nuxt') || !!window.__NUXT__,
                gatsby: !!window.___gatsby || !!document.getElementById('gatsby-focus-wrapper'),
                ember: !!window.Ember,
                backbone: !!window.Backbone,
                // CSS Frameworks
                bootstrap: !!window.bootstrap || !!document.querySelector('.navbar-toggler,.btn.btn-primary'),
                tailwind: Array.from(document.querySelectorAll('[class]')).some(el =>
                    /\b(text-|bg-|flex|grid|p-\d|m-\d|rounded|shadow)/.test(el.className)),
                // Analytics
                ga: !!window.ga || !!window.gtag || all.includes('google-analytics'),
                gtm: !!window.dataLayer || all.includes('googletagmanager'),
                fbPixel: !!window.fbq || all.includes('fbevents'),
                hotjar: !!window.hj || all.includes('hotjar'),
                segment: !!window.analytics && !!window.analytics.track,
                mixpanel: !!window.mixpanel,
                clarity: !!window.clarity,
                // Commerce / Auth
                stripe: !!window.Stripe || all.includes('stripe.com'),
                recaptcha: !!window.grecaptcha,
                intercom: !!window.Intercom,
                zendesk: !!window.zE || !!window.zESettings,
                hubspot: !!window._hsq || all.includes('hs-scripts.com'),
                // JQuery
                jquery: !!window.jQuery,
                // Misc
                cloudflare: all.includes('cloudflare'),
            };
        });

        await browser.close();
        browser = null;

        // ── Build detection buckets ──────────────────────────────────────────────
        const det = {
            frontend: [],
            backend: [],
            cms: [],
            server: [],
            cdn: [],
            analytics_and_marketing: [],
            database_and_caching: [],
            other_tech: []
        };

        // 1. Web Server
        if (serverHdr.includes('apache')) det.server.push('Apache');
        if (serverHdr.includes('nginx')) det.server.push('Nginx');
        if (serverHdr.includes('iis') || serverHdr.includes('microsoft-iis')) det.server.push('IIS');
        if (serverHdr.includes('litespeed')) det.server.push('LiteSpeed');
        if (serverHdr.includes('gunicorn')) det.server.push('Gunicorn');
        if (serverHdr.includes('caddy')) det.server.push('Caddy');
        if (serverHdr.includes('openresty')) det.server.push('OpenResty');

        // 2. Backend
        if (xPoweredBy.includes('php') || serverHdr.includes('php') || resHeaders['x-php-version'])
            det.backend.push('PHP');
        if (xPoweredBy.includes('express') || xPoweredBy.includes('node') || resHeaders['x-node-version'])
            det.backend.push('Node.js / Express');
        if (xPoweredBy.includes('asp.net') || resHeaders['x-aspnet-version'])
            det.backend.push('ASP.NET');
        if (xPoweredBy.includes('next.js'))
            det.backend.push('Next.js (SSR)');
        if (xPoweredBy.includes('rails') || resHeaders['x-rack-cache'])
            det.backend.push('Ruby on Rails');
        if (cookieHdr.includes('phpsessid') && !det.backend.includes('PHP')) det.backend.push('PHP');
        if (cookieHdr.includes('asp.net_sessionid') && !det.backend.includes('ASP.NET')) det.backend.push('ASP.NET');
        if (cookieHdr.includes('jsessionid')) det.backend.push('Java (J2EE)');
        if (rawHtml.includes('csrfmiddlewaretoken')) det.backend.push('Django (Python)');
        if (resHeaders['x-laravel-data']) det.backend.push('Laravel (PHP)');

        // 3. CMS
        if (generatorMeta.includes('wordpress') || rawHtml.includes('wp-content') || rawHtml.includes('wp-includes'))
            det.cms.push('WordPress');
        if (generatorMeta.includes('joomla') || (resHeaders['x-content-encoded-by'] || '').includes('joomla'))
            det.cms.push('Joomla');
        if (generatorMeta.includes('drupal') || resHeaders['x-drupal-cache'])
            det.cms.push('Drupal');
        if (generatorMeta.includes('wix') || resHeaders['x-wix-request-id'])
            det.cms.push('Wix');
        if (resHeaders['x-shopify-stage'] || rawHtml.includes('cdn.shopify.com'))
            det.cms.push('Shopify');
        if (generatorMeta.includes('squarespace') || rawHtml.includes('squarespace.com'))
            det.cms.push('Squarespace');
        if (generatorMeta.includes('ghost') || rawHtml.includes('content="Ghost'))
            det.cms.push('Ghost');
        if (rawHtml.includes('Magento') || generatorMeta.includes('magento'))
            det.cms.push('Magento');
        if (rawHtml.includes('data-webflow-domain'))
            det.cms.push('Webflow');

        // 4. Frontend (from Puppeteer JS evaluation)
        if (jsFingerprints.react) det.frontend.push('React');
        if (jsFingerprints.vue) det.frontend.push('Vue.js');
        if (jsFingerprints.angular) det.frontend.push('Angular');
        if (jsFingerprints.svelte) det.frontend.push('Svelte');
        if (jsFingerprints.nextjs) det.frontend.push('Next.js');
        if (jsFingerprints.nuxt) det.frontend.push('Nuxt.js');
        if (jsFingerprints.gatsby) det.frontend.push('Gatsby');
        if (jsFingerprints.ember) det.frontend.push('Ember.js');
        if (jsFingerprints.backbone) det.frontend.push('Backbone.js');
        if (jsFingerprints.bootstrap) det.frontend.push('Bootstrap');
        if (jsFingerprints.tailwind) det.frontend.push('Tailwind CSS');

        // 5. CDN
        if (resHeaders['cf-ray'] || serverHdr.includes('cloudflare') || jsFingerprints.cloudflare)
            det.cdn.push('Cloudflare');
        if (resHeaders['x-varnish']) det.cdn.push('Varnish Cache');
        const via = resHeaders['via'] || '';
        const xcache = resHeaders['x-cache'] || '';
        if (via.includes('cloudfront') || xcache.includes('cloudfront')) det.cdn.push('Amazon CloudFront');
        if (serverHdr.includes('akamai')) det.cdn.push('Akamai');
        if ((resHeaders['x-served-by'] || '').includes('fastly')) det.cdn.push('Fastly');

        // 6. Analytics & Marketing
        if (jsFingerprints.ga) det.analytics_and_marketing.push('Google Analytics');
        if (jsFingerprints.gtm) det.analytics_and_marketing.push('Google Tag Manager');
        if (jsFingerprints.fbPixel) det.analytics_and_marketing.push('Facebook Pixel');
        if (jsFingerprints.hotjar) det.analytics_and_marketing.push('Hotjar');
        if (jsFingerprints.segment) det.analytics_and_marketing.push('Segment');
        if (jsFingerprints.mixpanel) det.analytics_and_marketing.push('Mixpanel');
        if (jsFingerprints.clarity) det.analytics_and_marketing.push('Microsoft Clarity');
        if (jsFingerprints.hubspot) det.analytics_and_marketing.push('HubSpot');

        // 7. Database footprints
        if (det.cms.includes('WordPress') || det.cms.includes('Joomla'))
            det.database_and_caching.push('MySQL / MariaDB');
        if (det.cms.includes('Magento')) det.database_and_caching.push('Redis (Likely)');

        // 8. Other tools
        if (jsFingerprints.jquery) det.other_tech.push('jQuery');
        if (jsFingerprints.stripe) det.other_tech.push('Stripe Payments');
        if (jsFingerprints.recaptcha) det.other_tech.push('Google reCAPTCHA');
        if (jsFingerprints.intercom) det.other_tech.push('Intercom');
        if (jsFingerprints.zendesk) det.other_tech.push('Zendesk');
        if (rawHtml.includes('salesforce.com')) det.other_tech.push('Salesforce');

        // Python results
        const pyRes = await pythonPromise;
        if (pyRes.python_status === 'success') {
            if (pyRes.title) det.other_tech.push(`Page Title: ${pyRes.title}`);
            if (pyRes.basic_xss_risk) det.other_tech.push('⚠️ XSS Risk Signals (eval/innerHTML detected)');
        }

        // Deduplicate
        Object.keys(det).forEach(k => { det[k] = [...new Set(det[k])]; });

        return { url, status: httpStatus, detections: det };

    } catch (err) {
        if (browser) { try { await browser.close(); } catch { } }
        console.error('Error scanning URL:', err.message);
        throw new Error(`Failed to analyze: ${err.message}`);
    }
}

module.exports = { scanUrl };
