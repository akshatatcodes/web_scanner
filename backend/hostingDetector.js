/**
 * Hosting Provider Detector
 */
async function detect(dnsData, headerData) {
    const ip = dnsData.ip ? dnsData.ip.join(' ') : '';
    const server = (headerData.server || '').toLowerCase();

    // Simple IP-based and Header-based logic
    if (ip.includes('104.') || server.includes('cloudflare')) return 'Cloudflare';
    if (ip.includes('34.201') || ip.includes('52.216')) return 'AWS';
    if (ip.includes('34.102') || ip.includes('35.190')) return 'Google Cloud';
    if (server.includes('github.com')) return 'GitHub Pages';
    if (server.includes('netlify')) return 'Netlify';
    if (server.includes('vercel')) return 'Vercel';
    if (dnsData.mx && dnsData.mx.some(m => m.includes('google.com'))) return 'Google Workspace (Mail)';

    return 'Unknown Provider';
}

module.exports = { detect };
