/**
 * Report Persistence Layer
 * Handles saving and retrieving generated reports from disk.
 */

const fs = require('fs').promises;
const path = require('path');

const REPORTS_DIR = path.join(__dirname, '../reports');

/**
 * Ensures the reports directory exists.
 */
async function ensureDirectory() {
    try {
        await fs.mkdir(REPORTS_DIR, { recursive: true });
    } catch (err) {
        if (err.code !== 'EEXIST') throw err;
    }
}

/**
 * Saves a report buffer to disk.
 * @param {string} jobId 
 * @param {string} format 'pdf' | 'html'
 * @param {Buffer|string} content 
 */
async function saveReport(jobId, format, content) {
    await ensureDirectory();
    const fileName = `${jobId}.${format}`;
    const filePath = path.join(REPORTS_DIR, fileName);
    await fs.writeFile(filePath, content);
    return filePath;
}

/**
 * Retrieves a report from disk if it exists.
 * @param {string} jobId 
 * @param {string} format 
 */
async function getReport(jobId, format) {
    const fileName = `${jobId}.${format}`;
    const filePath = path.join(REPORTS_DIR, fileName);
    try {
        await fs.access(filePath);
        return filePath;
    } catch {
        return null;
    }
}

module.exports = {
    saveReport,
    getReport,
    REPORTS_DIR
};
