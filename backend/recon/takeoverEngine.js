const dns = require('dns').promises;
const axios = require('axios');
const { safeRequest } = require('./utils');

const TAKEOVER_FINGERPRINTS = {
  "amazonaws.com": "NoSuchBucket",
  "github.io": "There isn't a GitHub Pages site here",
  "herokuapp.com": "No such app",
  "ghost.io": "The thing you were looking for is no longer here",
  "pantheon.io": "404 error unknown site",
  "surge.sh": "project not found",
  "wordpress.com": "Do you want to register",
  "zendesk.com": "Help Center Closed",
  "readme.io": "Project doesnt exist",
  "vercel.app": "404: NOT_FOUND"
};

const checkTakeover = async (subdomain) => {
    try {
        let cnames;
        try {
           cnames = await dns.resolveCname(subdomain);
        } catch(e) { return null; }
        
        if (!cnames || cnames.length === 0) return null;
        
        let cname = cnames[0].toLowerCase();
        let targetProvider = null;
        let fingerprint = null;

        for (const [provider, fp] of Object.entries(TAKEOVER_FINGERPRINTS)) {
           if (cname.includes(provider)) {
               targetProvider = provider;
               fingerprint = fp;
               break;
           }
        }

        if (targetProvider) {
            // Found a CNAME to a known cloud provider. Let's verify dangling state.
            const url = `http://${subdomain}`;
            const res = await safeRequest(() => axios.get(url, { 
                timeout: 5000, 
                validateStatus: () => true 
            }), 2);

            let confirmed = false;
            if (res && res.data && typeof res.data === 'string') {
               if (res.data.includes(fingerprint)) {
                   confirmed = true;
               }
            }

            return {
                subdomain,
                cname,
                provider: targetProvider,
                confirmed,
                risk: confirmed ? "CRITICAL" : "HIGH", // Still HIGH risk because the CNAME resolves to external cloud
                message: confirmed ? `Confirmed Subdomain Takeover via ${targetProvider}` : `Potential Dangling CNAME to ${targetProvider}`
            };
        }
    } catch(err) {}
    
    return null;
};

module.exports = { checkTakeover };
