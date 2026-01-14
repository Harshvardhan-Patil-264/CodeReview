const { v4: uuidv4 } = require('uuid');

/**
 * In-memory scan manager
 * Tracks scan history and metadata
 */
class ScanManager {
    constructor() {
        this.scans = new Map();
    }

    /**
     * Create a new scan entry
     * @param {string} type - 'github' or 'upload'
     * @param {string} input - GitHub URL or upload filename
     * @returns {string} - Scan ID
     */
    createScan(type, input) {
        const scanId = `scan_${Date.now()}_${uuidv4().split('-')[0]}`;

        const scan = {
            id: scanId,
            type: type,
            input: input,
            status: 'pending',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            reportPaths: [],  // Array of report file names
            reportCount: 0,
            error: null,
            duration: null
        };

        this.scans.set(scanId, scan);
        console.log(`Created scan: ${scanId}`);

        return scanId;
    }

    /**
     * Update scan status
     */
    updateScan(scanId, updates) {
        const scan = this.scans.get(scanId);
        if (!scan) {
            throw new Error(`Scan not found: ${scanId}`);
        }

        Object.assign(scan, updates, {
            updatedAt: new Date().toISOString()
        });

        this.scans.set(scanId, scan);
        console.log(`Updated scan ${scanId}:`, updates);
    }

    /**
     * Get scan by ID
     */
    getScan(scanId) {
        return this.scans.get(scanId);
    }

    /**
     * Get all scans (sorted by creation date, newest first)
     */
    getAllScans() {
        const scans = Array.from(this.scans.values());
        return scans.sort((a, b) =>
            new Date(b.createdAt) - new Date(a.createdAt)
        );
    }

    /**
     * Mark scan as completed
     */
    completeScan(scanId, reportPaths, duration) {
        this.updateScan(scanId, {
            status: 'completed',
            reportPaths: reportPaths,  // Array of reports
            reportCount: reportPaths.length,
            duration: duration
        });
    }

    /**
     * Mark scan as failed
     */
    failScan(scanId, error) {
        this.updateScan(scanId, {
            status: 'failed',
            error: error
        });
    }
}

module.exports = new ScanManager();
