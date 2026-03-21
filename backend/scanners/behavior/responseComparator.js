/**
 * Calculates a heuristic divergence score between normal and injected responses.
 */
const compareResponses = (baseline, test) => {
    if (!baseline || !test) return 0;

    let score = 0;

    // Status code difference usually denotes a crash (500), Auth bypass (200 instead of 401), or WAF block (403)
    if (baseline.status !== test.status) score += 20;

    // Absolute length drastically changed
    if (Math.abs(baseline.length - test.length) > 50) score += 20;

    // Time dramatically increased
    if (Math.abs(baseline.time - test.time) > 2000) score += 30;

    return score;
};

module.exports = { compareResponses };
