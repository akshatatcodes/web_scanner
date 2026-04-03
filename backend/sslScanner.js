const tls = require('tls');
const https = require('https');
const http = require('http');

/**
 * SSL/TLS Security Scanner Module
 */
class SSLScanner {
    /**
     * Scan a target for SSL/TLS configuration
     * @param {string} url - Target URL
     */
    async scan(url) {
        try {
            const targetUrl = url.startsWith('http') ? url : `https://${url}`;
            const hostname = new URL(targetUrl).hostname;
            const certInfo = await this.getCertificate(hostname);
            const httpsEnforced = await this.checkHttpsEnforcement(hostname);

            return {
                ...certInfo,
                httpsEnforced,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            console.error('[SSL Scanner Error]:', error.message);
            return {
                valid: false,
                error: error.message,
                protocol: 'Not Available',
                isProtocolSecure: false,
                cipher: 'Not Available',
                issuer: 'Not Available',
                remainingDays: 0,
                timestamp: new Date().toISOString()
            };
        }
    }

    /**
     * Connect via TLS and extract certificate/protocol info
     */
    async getCertificate(hostname) {
        return new Promise((resolve, reject) => {
            const options = {
                hostname: hostname,
                port: 443,
                method: 'GET',
                rejectUnauthorized: false, // We want to inspect even invalid certs
                servername: hostname
            };

            const req = https.request(options, (res) => {
                const socket = res.socket;
                const cert = socket.getPeerCertificate(true);
                const protocol = socket.getProtocol();
                const cipher = socket.getCipher();

                if (!cert || Object.keys(cert).length === 0) {
                    resolve({
                        valid: false,
                        error: 'No certificate found',
                        protocol: protocol || 'Not Available',
                        isProtocolSecure: false,
                        cipher: cipher ? cipher.name : 'Not Available',
                        issuer: 'Not Available',
                        remainingDays: 0
                    });
                    return;
                }

                const now = new Date();
                const validTo = new Date(cert.valid_to);
                const validFrom = new Date(cert.valid_from);
                const isExpired = now > validTo;
                const isNotYetValid = now < validFrom;

                // Detection for weak protocols
                const insecureProtocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'];
                const isProtocolSecure = !insecureProtocols.includes(protocol);

                resolve({
                    valid: !isExpired && !isNotYetValid,
                    subject: cert.subject?.CN || 'Unknown',
                    issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
                    validFrom: cert.valid_from,
                    validTo: cert.valid_to,
                    remainingDays: Math.floor((validTo - now) / (1000 * 60 * 60 * 24)),
                    protocol: protocol || 'Not Available',
                    isProtocolSecure,
                    cipher: cipher ? cipher.name : 'Not Available',
                    bits: cipher ? cipher.bits : null,
                    fingerprint: cert.fingerprint
                });
            });

            req.on('error', (e) => {
                resolve({ 
                    valid: false, 
                    error: e.message,
                    protocol: 'Not Available',
                    cipher: 'Not Available',
                    issuer: 'Not Available',
                    remainingDays: 0
                });
            });

            req.on('timeout', () => {
                req.destroy();
                resolve({ 
                    valid: false, 
                    error: 'Connection timeout',
                    protocol: 'Not Available',
                    cipher: 'Not Available',
                    issuer: 'Not Available',
                    remainingDays: 0 
                });
            });

            req.setTimeout(5000);
            req.end();
        });
    }

    /**
     * Check if HTTPS is enforced (redirects from HTTP to HTTPS)
     */
    async checkHttpsEnforcement(hostname) {
        return new Promise((resolve) => {
            http.get(`http://${hostname}`, { timeout: 3000 }, (res) => {
                resolve(res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 308);
            }).on('error', () => {
                resolve(false);
            });
        });
    }
}

module.exports = new SSLScanner();
