/**
 * Hosting Provider Detector
 */
async function detect(dnsData, headerData) {
    const ip = dnsData.ip ? dnsData.ip.join(' ') : '';
    const server = (headerData.server || '').toLowerCase();

    // Expanded IP-based and Header-based logic
    const isCloudflare = ip.includes('104.') || ip.includes('172.') || server.includes('cloudflare');
    const isAWS = ip.includes('34.201') || ip.includes('52.216') || ip.includes('54.239') || server.includes('amazon') || server.includes('aws');
    const isGoogle = ip.includes('34.102') || ip.includes('35.190') || server.includes('google') || server.includes('gws') || server.includes('ghs');

    if (isCloudflare) return 'Cloudflare';
    if (isAWS) return 'Amazon Web Services (AWS)';
    if (isGoogle) return 'Google Cloud / Google Infrastructure';
    if (server.includes('github.com')) return 'GitHub Pages';
    if (server.includes('netlify')) return 'Netlify';
    if (server.includes('vercel')) return 'Vercel';
    if (server.includes('fastly')) return 'Fastly';
    if (server.includes('akamai')) return 'Akamai';
    if (server.includes('apache')) return 'Apache Web Server';
    if (server.includes('nginx')) return 'Nginx Web Server';
    if (server.includes('litespeed')) return 'LiteSpeed Web Server';

    if (dnsData.mx && dnsData.mx.some(m => m.includes('google.com'))) return 'Google Workspace (Mail)';
    if (dnsData.mx && dnsData.mx.some(m => m.includes('outlook.com'))) return 'Microsoft 365 (Mail)';
    if (dnsData.mx && dnsData.mx.some(m => m.includes('secureserver.net'))) return 'GoDaddy';

    return 'Unknown Provider';
}

module.exports = { detect };
