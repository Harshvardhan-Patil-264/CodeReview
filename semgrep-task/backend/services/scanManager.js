const { v4: uuidv4 } = require('uuid');
const Scan = require('../models/Scan');

/**
 * Database-backed scan manager
 * Stores scan metadata and status in MySQL database
 */

/**
 * Create a new scan entry
 * @param {string} userId - User ID who owns this scan
 * @param {string} type - 'github' or 'upload'
 * @param {string} input - GitHub URL or uploaded file name
 * @returns {Promise<Object>} Scan object
 */
async function createScan(userId, type, input) {
    const scanId = `scan_${Date.now()}_${uuidv4().split('-')[0]}`;

    const scan = await Scan.create({
        id: scanId,
        userId: userId,
        type: type,
        input: input,
        status: 'pending',
        reportPaths: [],
        reportCount: 0,
    });

    console.log(`[ScanManager] Created scan: ${scanId} for user: ${userId}`);
    return scan;
}

/**
 * Mark scan as completed
 * @param {string} scanId - Scan ID
 * @param {string[]} reportPaths - Array of report paths
 * @param {number} duration - Scan duration in ms
 * @returns {Promise<Object>} Updated scan object
 */
async function completeScan(scanId, reportPaths, duration) {
    const scan = await Scan.findByPk(scanId);

    if (!scan) {
        console.error(`[ScanManager] Scan not found: ${scanId}`);
        throw new Error(`Scan not found: ${scanId}`);
    }

    await scan.markCompleted(reportPaths, duration);
    console.log(`[ScanManager] Scan completed: ${scanId} with ${scan.reportCount} report(s)`);

    return scan;
}

/**
 * Mark scan as failed
 * @param {string} scanId - Scan ID
 * @param {string} error - Error message
 * @returns {Promise<Object>} Updated scan object
 */
async function failScan(scanId, error) {
    const scan = await Scan.findByPk(scanId);

    if (!scan) {
        console.error(`[ScanManager] Scan not found: ${scanId}`);
        throw new Error(`Scan not found: ${scanId}`);
    }

    await scan.markFailed(error);
    console.log(`[ScanManager] Scan failed: ${scanId} - ${error}`);

    return scan;
}

/**
 * Get all scans for a specific user
 * @param {string} userId - User ID
 * @returns {Promise<Array>} Array of user's scans
 */
async function getAllScans(userId) {
    const scans = await Scan.findAll({
        where: { userId },
        order: [['createdAt', 'DESC']],
    });

    return scans;
}

/**
 * Get scan by ID
 * @param {string} scanId - Scan ID
 * @param {string} userId - User ID (optional, for ownership verification)
 * @returns {Promise<Object|null>} Scan object or null if not found
 */
async function getScan(scanId, userId = null) {
    const where = { id: scanId };

    // If userId provided, verify ownership
    if (userId) {
        where.userId = userId;
    }

    const scan = await Scan.findOne({ where });
    return scan;
}

module.exports = {
    createScan,
    completeScan,
    failScan,
    getAllScans,
    getScan
};
