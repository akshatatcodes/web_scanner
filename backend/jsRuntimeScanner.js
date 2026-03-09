/**
 * JavaScript Runtime Scanner
 * Probes global variables for frameworks.
 */
async function scan(page) {
    return await page.evaluate(() => {
        const tech = [];

        if (window.jQuery) tech.push({ name: 'jQuery', version: window.jQuery.fn.jquery });
        if (window.React || document.querySelector('[data-reactroot]')) tech.push({ name: 'React' });
        if (window.Vue || document.querySelector('[data-v-')) tech.push({ name: 'Vue.js' });
        if (window.ng || window.angular) tech.push({ name: 'Angular' });
        if (window.__NEXT_DATA__) tech.push({ name: 'Next.js' });
        if (window.$nuxt || window.__NUXT__) tech.push({ name: 'Nuxt.js' });
        if (window.bootstrap && window.bootstrap.Alert) tech.push({ name: 'Bootstrap' });

        return tech;
    });
}

module.exports = { scan };
