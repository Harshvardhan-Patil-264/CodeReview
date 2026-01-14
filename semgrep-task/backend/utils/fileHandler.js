const AdmZip = require('adm-zip');
const path = require('path');
const fs = require('fs');

/**
 * File handling utilities
 * Extract ZIP files and cleanup temp files
 */
class FileHandler {
    constructor() {
        this.uploadsDir = path.join(__dirname, '..', 'uploads');

        // Ensure uploads directory exists
        if (!fs.existsSync(this.uploadsDir)) {
            fs.mkdirSync(this.uploadsDir, { recursive: true });
        }
    }

    /**
     * Extract ZIP file to temporary directory
     * @param {string} zipPath - Path to ZIP file
     * @param {string} extractDir - Directory to extract to
     * @returns {string} - Path to extracted directory
     */
    extractZip(zipPath, extractDir) {
        try {
            console.log(`Extracting ZIP: ${zipPath} to ${extractDir}`);

            const zip = new AdmZip(zipPath);
            zip.extractAllTo(extractDir, true);

            console.log(`Extraction completed: ${extractDir}`);
            return extractDir;
        } catch (error) {
            console.error('Failed to extract ZIP:', error);
            throw new Error(`Failed to extract ZIP file: ${error.message}`);
        }
    }

    /**
     * Clean up temporary files and directories
     * @param {string} filePath - Path to file or directory
     */
    cleanup(filePath) {
        try {
            if (!fs.existsSync(filePath)) {
                return;
            }

            const stat = fs.statSync(filePath);

            if (stat.isDirectory()) {
                // Remove directory recursively
                fs.rmSync(filePath, { recursive: true, force: true });
                console.log(`Cleaned up directory: ${filePath}`);
            } else {
                // Remove file
                fs.unlinkSync(filePath);
                console.log(`Cleaned up file: ${filePath}`);
            }
        } catch (error) {
            console.error(`Failed to cleanup ${filePath}:`, error);
        }
    }

    /**
     * Get file size in bytes
     */
    getFileSize(filePath) {
        try {
            const stat = fs.statSync(filePath);
            return stat.size;
        } catch (error) {
            return 0;
        }
    }

    /**
     * Check if file exists
     */
    fileExists(filePath) {
        return fs.existsSync(filePath);
    }
}

module.exports = new FileHandler();
