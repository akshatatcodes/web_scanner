const axios = require('axios');
const { safeRequest } = require('../../recon/utils');

/**
 * Establishes the baseline normal behavior of an endpoint before any injection.
 */
const getBaseline = async (url, method = 'GET') => {
    const start = Date.now();
    const res = await safeRequest(() => axios({
        method,
        url,
        timeout: 8000,
        validateStatus: () => true
    }), 2);
    
    const time = Date.now() - start;

    if (!res) return null;

    return {
        status: res.status,
        length: res.data ? JSON.stringify(res.data).length : 0,
        time,
        headers: res.headers,
        bodyExcerpt: res.data && typeof res.data === 'string' ? res.data.substring(0, 500) : ''
    };
};

/**
 * Detects objective anomalies between a baseline request and an injected request.
 */
const detectAnomaly = (baseline, test) => {
    if (!baseline || !test) return null;

    return {
        timeAnomaly: test.time > baseline.time + 3000, // E.g., at least 3 seconds slower
        sizeAnomaly: Math.abs(test.length - baseline.length) > 100, // Significant content shift
        statusChange: baseline.status !== test.status
    };
};

module.exports = { getBaseline, detectAnomaly };
