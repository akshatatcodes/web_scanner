/**
 * Network Fingerprinting Scanner
 * Detects technologies via network requests.
 */
async function scan(page) {
    const requests = [];

    // Listen for requests
    page.on('request', req => {
        requests.push(req.url());
    });

    // Wait slightly for network traffic to settle
    await new Promise(resolve => setTimeout(resolve, 2000));

    const technologies = [];
    const urlString = requests.join(' ');

    if (urlString.includes('google-analytics.com')) technologies.push('Google Analytics');
    if (urlString.includes('googletagmanager.com/gtm.js')) technologies.push('Google Tag Manager');
    if (urlString.includes('connect.facebook.net')) technologies.push('Facebook Pixel');
    if (urlString.includes('cdn.jsdelivr.net')) technologies.push('jsDelivr CDN');
    if (urlString.includes('fonts.googleapis.com')) technologies.push('Google Fonts');
    if (urlString.includes('hotjar.com')) technologies.push('Hotjar');
    if (urlString.includes('mixpanel.com')) technologies.push('Mixpanel');
    if (urlString.includes('doubleclick.net')) technologies.push('DoubleClick');
    if (urlString.includes('amazon-adsystem.com')) technologies.push('Amazon Advertising');

    return technologies;
}

module.exports = { scan };
