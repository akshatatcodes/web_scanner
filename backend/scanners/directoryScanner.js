const axios = require('axios');

const COMMON_PATHS = [
  "/.git/config", "/backup", "/config", "/api", "/admin", "/.env",
  "/server-status", "/phpinfo.php", "/wp-admin", "/test",
  "/.vscode/settings.json", "/docker-compose.yml", "/package.json",
  "/swagger.json", "/api-docs"
];

const BATCH_SIZE = 5; // Concurrency limit

const scanDirectories = async (baseUrl) => {
  const findings = [];
  const urlBase = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;

  for (let i = 0; i < COMMON_PATHS.length; i += BATCH_SIZE) {
    const batch = COMMON_PATHS.slice(i, i + BATCH_SIZE);
    
    await Promise.all(batch.map(async (path) => {
      try {
        const url = `${urlBase}${path}`;
        const res = await axios.get(url, {
          timeout: 5000,
          validateStatus: () => true, // resolve on any status
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scanner' }
        });

        if ([200, 401, 403].includes(res.status)) {
            // Basic heuristic to avoid Soft 404s
            const isSoft404 = res.status === 200 && 
                typeof res.data === 'string' && 
                (res.data.toLowerCase().includes('not found') || res.data.toLowerCase().includes('404'));
            
            if (!isSoft404) {
                findings.push({
                    type: "DIRECTORY_BRUTE",
                    severity: res.status === 200 ? "HIGH" : "MEDIUM",
                    url,
                    status: res.status,
                    message: `Exposed directory/file found (Status: ${res.status})`
                });
            }
        }
      } catch (err) {
        // Ignore network errors/timeouts
      }
    }));
  }

  return findings;
};

module.exports = { scanDirectories };
