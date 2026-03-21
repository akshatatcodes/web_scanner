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
        console.log(`[Port Scanner] Starting concurrent scan for ${host}...`);
        
        // Scan ports in parallel
        const workers = COMMON_PORTS.map(port => checkPort(host, port));
        const results = await Promise.all(workers);

        const openPorts = results
            .filter(r => r.status === 'open')
            .map(r => ({
                port: r.port,
                service: PORT_SERVICES[r.port] || 'Unknown Service',
                status: 'open'
            }));

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
        socket.setTimeout(1500); // 1.5 second timeout

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
