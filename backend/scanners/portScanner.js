const net = require('net');
const attackLogger = require('../utils/attackLogger');

/**
 * Common Ports Mapping
 */
const COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 
    993, 995, 1433, 1521, 2082, 2083, 2086, 2087, 2095, 2096, 
    3000, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 9000, 27017
];

const PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2082: "cPanel (HTTP)",
    2083: "cPanel (HTTPS)",
    2086: "WHM (HTTP)",
    2087: "WHM (HTTPS)",
    2095: "Webmail (HTTP)",
    2096: "Webmail (HTTPS)",
    3000: "Node.js / React / Dev",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP/Dev",
    8080: "HTTP Proxy / Jenkins",
    8443: "HTTPS Proxy",
    9000: "PHP-FPM / FastCGI",
    27017: "MongoDB"
};

/**
 * High-Concurrency Port Scanner
 * Detects open ports and identifies likely services.
 */
async function scan(host) {
    try {
        console.log(`[Port Scanner] Starting reliable scan for ${host}...`);
        
        const openPorts = [];
        const CONCURRENCY = 10;
        const RETRIES = 2;
        
        // Process ports in chunks to control concurrency
        for (let i = 0; i < COMMON_PORTS.length; i += CONCURRENCY) {
            const chunk = COMMON_PORTS.slice(i, i + CONCURRENCY);
            const chunkPromises = chunk.map(async (port) => {
                let lastResult = { status: 'closed' };
                
                // Retry logic
                for (let attempt = 0; attempt <= RETRIES; attempt++) {
                    lastResult = await checkPort(host, port);
                    if (lastResult.status === 'open') break;
                    if (attempt < RETRIES) {
                        // Small backoff between retries
                        await new Promise(r => setTimeout(r, 200 * (attempt + 1)));
                    }
                }
                
                if (lastResult.status === 'open') {
                    return {
                        port: lastResult.port,
                        service: PORT_SERVICES[lastResult.port] || 'Unknown Service',
                        status: 'open'
                    };
                }
                return null;
            });

            const results = await Promise.all(chunkPromises);
            openPorts.push(...results.filter(Boolean));
            
            // Adaptive delay between chunks
            if (i + CONCURRENCY < COMMON_PORTS.length) {
                await new Promise(r => setTimeout(r, 150));
            }
        }

        if (openPorts.length > 0) {
            const portList = openPorts.map(p => p.port).join(', ');
            attackLogger.log({ type: 'INFO', scanner: 'PortScanner', target: host, result: `Open ports found: ${portList}` });
        }

        console.log(`[Port Scanner] Found ${openPorts.length} open ports.`);
        return openPorts;

    } catch (error) {
        console.error('[Port Scanner] Fatal Error:', error.message);
        return [];
    }
}

/**
 * Individual Port Check with Timeout
 */
function checkPort(host, port) {
    return new Promise(resolve => {
        const socket = new net.Socket();
        socket.setTimeout(3000); // 3 second timeout (increased from 1.5s)

        socket
            .connect(port, host, () => {
                socket.destroy();
                resolve({ port, status: 'open' });
            })
            .on('error', () => {
                socket.destroy();
                resolve({ port, status: 'closed' });
            })
            .on('timeout', () => {
                socket.destroy();
                resolve({ port, status: 'filtered' });
            });
    });
}

module.exports = { scan };
