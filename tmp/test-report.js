const { generatePdf, generateHtml } = require('../backend/utils/reportGenerator');
const fs = require('fs').promises;
const path = require('path');

const sampleResults = {
    url: 'https://example.com',
    target: 'example.com',
    timestamp: new Date().toISOString(),
    scanDuration: '12.5s',
    vulnerabilities: {
        'Express': [
            { id: 'CVE-2022-24999', severity: 'HIGH', score: 7.5, description: 'Sample high vulnerability in Express.', published: '2022-01-01' }
        ],
        'Injection': [
            { type: 'SQL_INJECTION', severity: 'CRITICAL', title: 'SQL Injection at /api/users', endpoint: '/api/users', payload: "' OR 1=1--", evidence: 'SQL syntax error' }
        ]
    },
    cookieSecurity: [],
    suspiciousScripts: [],
    scanContext: { stats: { uniqueEndpoints: 42 } }
};

async function verify() {
    try {
        const html = generateHtml(sampleResults);
        await fs.writeFile(path.join(__dirname, 'test-proper.html'), html);
        console.log('✅ Proper HTML generated: tmp/test-proper.html');
        process.exit(0);
    } catch (err) {
        console.error('❌ Verification Failed:', err);
        process.exit(1);
    }
}
verify();
