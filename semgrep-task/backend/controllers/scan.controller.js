const path = require('path');
const fs = require('fs');
const pythonExecutor = require('../services/pythonExecutor');
const scanManager = require('../services/scanManager');
const fileHandler = require('../utils/fileHandler');
const { validateGitHubUrl, validateFileUpload } = require('../middleware/validation');

/**
 * POST /api/scan
 * Create a new scan (GitHub URL or uploaded folder)
 */
exports.createScan = async (req, res, next) => {
    try {
        const { type, url } = req.body;
        const file = req.file;

        let scanInput;
        let targetPath;
        let extractedDir = null;

        // Determine scan type and validate
        if (type === 'github') {
            // GitHub URL scan
            const validation = validateGitHubUrl(url);
            if (!validation.valid) {
                const error = new Error(validation.error);
                error.status = 400;
                error.code = 'INVALID_GITHUB_URL';
                throw error;
            }

            scanInput = url;
            targetPath = url;

        } else if (type === 'upload' || file) {
            // File upload scan
            const validation = validateFileUpload(file);
            if (!validation.valid) {
                const error = new Error(validation.error);
                error.status = 400;
                error.code = 'INVALID_FILE_UPLOAD';
                throw error;
            }

            scanInput = file.originalname;

            // Extract ZIP file
            const extractDir = path.join(__dirname, '..', 'uploads', `extract_${Date.now()}`);
            fs.mkdirSync(extractDir, { recursive: true });

            try {
                extractedDir = fileHandler.extractZip(file.path, extractDir);
                targetPath = extractedDir;
            } catch (error) {
                fileHandler.cleanup(file.path);
                fileHandler.cleanup(extractDir);
                throw error;
            }

        } else {
            const error = new Error('Invalid scan type. Must specify type=github with url, or upload a file');
            error.status = 400;
            error.code = 'INVALID_SCAN_TYPE';
            throw error;
        }

        // Get userId from authenticated user
        const userId = req.user.id;

        // Create scan entry with userId
        const scan = await scanManager.createScan(userId, type || 'upload', scanInput);
        const scanId = scan.id;

        console.log(`[${req.requestId}] Starting scan ${scanId} for user ${userId}: ${scanInput}`);

        // Mark scan as running when execution starts
        await scan.markRunning();

        // Execute Python scan
        try {
            const result = await pythonExecutor.executeScan(targetPath, req.requestId);

            // Mark scan as completed with ALL report paths
            await scanManager.completeScan(scanId, result.reportPaths, result.duration);

            console.log(`[${req.requestId}] Scan completed: ${scanId} with ${result.reportCount} report(s)`);

            res.json({
                success: true,
                scanId: scanId,
                message: 'Scan completed successfully',
                reportPaths: result.reportPaths,  // Array of reports
                reportCount: result.reportCount,
                duration: result.duration
            });

        } catch (execError) {
            // Mark scan as failed
            await scanManager.failScan(scanId, execError.error || execError.message);

            console.error(`[${req.requestId}] Scan failed: ${scanId}`, execError);

            const error = new Error(execError.error || 'Scan execution failed');
            error.status = execError.status || 500;
            error.code = execError.code || 'SCAN_FAILED';
            throw error;

        } finally {
            // Cleanup uploaded file and extracted directory
            if (file) {
                fileHandler.cleanup(file.path);
            }
            if (extractedDir) {
                fileHandler.cleanup(extractedDir);
            }
        }

    } catch (error) {
        next(error);
    }
};

/**
 * GET /api/scans
 * Get all scans
 */
exports.getScans = async (req, res, next) => {
    try {
        // Get userId from authenticated user
        const userId = req.user.id;

        // Get only this user's scans
        const scans = await scanManager.getAllScans(userId);

        res.json({
            success: true,
            count: scans.length,
            scans: scans
        });
    } catch (error) {
        next(error);
    }
};

/**
 * GET /api/scans/:id
 * Get specific scan by ID
 */
exports.getScan = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;

        // Get scan and verify ownership
        const scan = await scanManager.getScan(id, userId);

        if (!scan) {
            const error = new Error(`Scan not found or access denied: ${id}`);
            error.status = 404;
            error.code = 'SCAN_NOT_FOUND';
            throw error;
        }

        res.json({
            success: true,
            scan: scan
        });
    } catch (error) {
        next(error);
    }
};

/**
 * GET /api/scans/:id/report
 * Download report for a specific scan
 * Returns the first report from the reportPaths array
 */
exports.getReport = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;

        // Get scan and verify ownership
        const scan = await scanManager.getScan(id, userId);

        if (!scan) {
            const error = new Error(`Scan not found or access denied: ${id}`);
            error.status = 404;
            error.code = 'SCAN_NOT_FOUND';
            throw error;
        }

        if (scan.status !== 'completed' || !scan.reportPaths || scan.reportPaths.length === 0) {
            const error = new Error(`Report not available for scan ${id}`);
            error.status = 400;
            error.code = 'REPORT_NOT_AVAILABLE';
            throw error;
        }

        // Use the first report (main report)
        const reportPath = scan.reportPaths[0];

        // Construct absolute path to report
        const absoluteReportPath = path.join(__dirname, '..', '..', reportPath);

        // Check if report exists
        if (!fileHandler.fileExists(absoluteReportPath)) {
            const error = new Error(`Report file not found: ${reportPath}`);
            error.status = 404;
            error.code = 'REPORT_FILE_NOT_FOUND';
            throw error;
        }

        console.log(`[${req.requestId}] Serving report: ${absoluteReportPath}`);

        // Send file with proper headers
        res.download(absoluteReportPath, reportPath, (err) => {
            if (err) {
                console.error(`[${req.requestId}] Failed to send report:`, err);
                if (!res.headersSent) {
                    const error = new Error('Failed to download report');
                    error.status = 500;
                    error.code = 'DOWNLOAD_FAILED';
                    next(error);
                }
            }
        });

    } catch (error) {
        next(error);
    }
};

/**
 * GET /api/scans/:id/reports/:index
 * Download a specific report by index from the reportPaths array
 */
exports.getReportByIndex = async (req, res, next) => {
    try {
        const { id, index } = req.params;
        const userId = req.user.id;

        // Get scan and verify ownership
        const scan = await scanManager.getScan(id, userId);

        if (!scan) {
            const error = new Error(`Scan not found or access denied: ${id}`);
            error.status = 404;
            error.code = 'SCAN_NOT_FOUND';
            throw error;
        }

        if (scan.status !== 'completed' || !scan.reportPaths || scan.reportPaths.length === 0) {
            const error = new Error(`Report not available for scan ${id}`);
            error.status = 400;
            error.code = 'REPORT_NOT_AVAILABLE';
            throw error;
        }

        const reportIndex = parseInt(index);
        if (isNaN(reportIndex) || reportIndex < 0 || reportIndex >= scan.reportPaths.length) {
            const error = new Error(`Invalid report index: ${index}. Available: 0-${scan.reportPaths.length - 1}`);
            error.status = 400;
            error.code = 'INVALID_REPORT_INDEX';
            throw error;
        }

        const reportPath = scan.reportPaths[reportIndex];

        // Construct absolute path to report
        const absoluteReportPath = path.join(__dirname, '..', '..', reportPath);

        // Check if report exists
        if (!fileHandler.fileExists(absoluteReportPath)) {
            const error = new Error(`Report file not found: ${reportPath}`);
            error.status = 404;
            error.code = 'REPORT_FILE_NOT_FOUND';
            throw error;
        }

        console.log(`[${req.requestId}] Serving report ${reportIndex}: ${absoluteReportPath}`);

        // Send file with proper headers
        const filename = reportPath.split('/').pop() || `report-${reportIndex}.xlsx`;
        res.download(absoluteReportPath, filename, (err) => {
            if (err) {
                console.error(`[${req.requestId}] Failed to send report:`, err);
                if (!res.headersSent) {
                    const error = new Error('Failed to download report');
                    error.status = 500;
                    error.code = 'DOWNLOAD_FAILED';
                    next(error);
                }
            }
        });

    } catch (error) {
        next(error);
    }
};

