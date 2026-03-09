/**
 * Asset URL Fingerprinting Scanner
 * Detects infrastructure via script/img/link URLs.
 */
async function scan(page) {
    const urls = await page.evaluate(() => {
        return Array.from(document.querySelectorAll('img, script, link'))
            .map(e => e.src || e.href)
            .filter(u => u && u.startsWith('http'));
    });

    const tech = [];
    const urlString = urls.join(' ');

    if (urlString.includes('cloudinary.com')) tech.push('Cloudinary');
    if (urlString.includes('shopify.com/cdn')) tech.push('Shopify CDN');
    if (urlString.includes('imgix.net')) tech.push('Imgix');
    if (urlString.includes('wp-content')) tech.push('WordPress Assets');
    if (urlString.includes('netdna-ssl.com')) tech.push('StackPath CDN');
    if (urlString.includes('akamai')) tech.push('Akamai CDN');
    if (urlString.includes('fastly')) tech.push('Fastly CDN');

    return Array.from(new Set(tech));
}

module.exports = { scan };
