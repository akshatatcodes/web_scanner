/**
 * Cookie Fingerprinting Scanner
 * Detects technologies via cookie patterns.
 */
async function scan(page) {
    const cookies = await page.cookies();
    const tech = [];

    cookies.forEach(c => {
        if (c.name.startsWith('_ga') || c.name === '_gid') tech.push('Google Analytics');
        if (c.name === '_fbp') tech.push('Facebook Pixel');
        if (c.name.includes('cf_')) tech.push('Cloudflare');
        if (c.name.includes('shopify')) tech.push('Shopify');
        if (c.name === 'PHPSESSID') tech.push('PHP Session');
        if (c.name === 'JSESSIONID') tech.push('Java/JSP Session');
        if (c.name === 'csrftoken') tech.push('Django/Python');
        if (c.name.includes('wp-settings')) tech.push('WordPress');
    });

    return Array.from(new Set(tech)); // Unique results
}

module.exports = { scan };
