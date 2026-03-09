const dns = require('dns').promises;

/**
 * DNS Scanner Module
 */
async function scan(url) {
    try {
        const domain = new URL(url).hostname;

        // Resolve in parallel
        const [a, mx, txt] = await Promise.allSettled([
            dns.resolve(domain, 'A'),
            dns.resolveMx(domain),
            dns.resolveTxt(domain)
        ]);

        return {
            ip: a.status === 'fulfilled' ? a.value : [],
            mx: mx.status === 'fulfilled' ? mx.value.map(m => m.exchange) : [],
            txt: txt.status === 'fulfilled' ? txt.value.flat() : []
        };
    } catch (error) {
        console.error('DNS Scanner Error:', error.message);
        return { error: 'Failed to resolve DNS' };
    }
}

module.exports = { scan };
