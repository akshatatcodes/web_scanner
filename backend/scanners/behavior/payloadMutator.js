/**
 * Dynamically mutates static payload definitions to evade basic WAF definitions.
 */
const mutate = (payload) => {
    if (!payload) return [];

    const mutations = new Set();
    mutations.add(payload);

    // 1. Space replacement bypass (e.g. from OR 1=1 to OR/**/1=1)
    if (payload.includes(' ')) {
        mutations.add(payload.replace(/ /g, "/**/"));
        mutations.add(payload.replace(/ /g, "%20"));
        mutations.add(payload.replace(/ /g, "+"));
    }

    // 2. Case variation bypass
    mutations.add(payload.toUpperCase());
    mutations.add(payload.toLowerCase());

    // 3. Null Byte injection termination
    mutations.add(`${payload}%00`);
    
    // 4. URL Double Encoding (for nested WAF/Proxy parsing)
    mutations.add(encodeURIComponent(encodeURIComponent(payload)));

    return Array.from(mutations);
};

module.exports = { mutate };
