const dns = require('dns').promises;
const axios = require('axios');
const { safeRequest } = require('./utils');

const parseAsn = async (domain) => {
    try {
        const records = await dns.resolve4(domain);
        if (!records || records.length === 0) return null;
        
        const mainIp = records[0];
        
        // Use free IP-API to get ASN context
        const response = await safeRequest(() => axios.get(`http://ip-api.com/json/${mainIp}?fields=status,message,country,isp,org,as,query`, { timeout: 5000 }));
        
        if (response && response.data && response.data.status === 'success') {
            const org = response.data.org.toLowerCase();
            const as = response.data.as.toLowerCase();
            
            // Check if it's a known cloud/CDN provider
            const cloudProviders = ['cloudflare', 'amazon', 'aws', 'google', 'fastly', 'akamai', 'microsoft', 'azure', 'imperva', 'incapsula'];
            const isCloud = cloudProviders.some(p => org.includes(p) || as.includes(p));
            
            return {
                ip: mainIp,
                asn: response.data.as,
                organization: response.data.org,
                isp: response.data.isp,
                isCloud,
                pivotPotential: isCloud ? 'LOW (WAF/CDN)' : 'HIGH (Direct Infrastructure)'
            };
        }
        
        return { ip: mainIp, asn: 'Unknown', isCloud: false };
    } catch (e) {
        return null;
    }
};

module.exports = { parseAsn };
