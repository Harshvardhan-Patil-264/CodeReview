const XLSX = require('xlsx');
const path = require('path');
const fs = require('fs');

/**
 * Parse an Excel report file and extract findings
 * @param {string} reportPath - Absolute path to the Excel file
 * @returns {Array} Array of finding objects
 */
function parseExcelReport(reportPath) {
    try {
        if (!fs.existsSync(reportPath)) {
            console.warn(`Report file not found: ${reportPath}`);
            return [];
        }

        const workbook = XLSX.readFile(reportPath);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];

        // Convert sheet to JSON
        const findings = XLSX.utils.sheet_to_json(sheet);

        return findings;
    } catch (error) {
        console.error(`Error parsing Excel report: ${reportPath}`, error);
        return [];
    }
}

/**
 * Calculate severity breakdown from findings
 * @param {Array} findings - Array of finding objects
 * @returns {Object} Severity counts { ERROR: 0, WARNING: 0, INFO: 0 }
 */
function calculateSeverityBreakdown(findings) {
    const breakdown = {
        ERROR: 0,
        WARNING: 0,
        INFO: 0
    };

    findings.forEach(finding => {
        const severity = finding.Severity?.toUpperCase();
        if (severity === 'ERROR') {
            breakdown.ERROR++;
        } else if (severity === 'WARNING') {
            breakdown.WARNING++;
        } else if (severity === 'INFO') {
            breakdown.INFO++;
        }
    });

    return breakdown;
}

/**
 * Calculate accuracy score based on ERROR severity only
 * 
 * Modified to focus purely on critical issues (ERRORS)
 * Warnings and Info are ignored in the accuracy calculation
 * 
 * Approach:
 * 1. Only count ERROR severity issues
 * 2. Use logarithmic scale to prevent harsh penalties
 * 3. Scale to 0-100 range
 * 
 * This gives realistic scores based on critical issues only:
 * - 0 errors = 100% (Perfect)
 * - 1 error = ~95% (Excellent)
 * - 5 errors = ~85% (Good)
 * - 10 errors = ~80% (Good)
 * - 20 errors = ~75% (Fair)
 * - 50 errors = ~65% (Fair)
 * - 100+ errors = <50% (Needs Improvement)
 * 
 * @param {Object} severityBreakdown - { ERROR: 0, WARNING: 0, INFO: 0 }
 * @returns {number} Accuracy score (0-100)
 */
function calculateAccuracyScore(severityBreakdown) {
    // Only consider ERROR severity
    const errorCount = severityBreakdown.ERROR;

    // If no errors, perfect score
    if (errorCount === 0) {
        return 100;
    }

    // Logarithmic scale with diminishing returns
    // This prevents extremely harsh penalties for high error counts
    // Formula: 100 - (log10(errorCount + 1) * scalingFactor)
    // Scaling factor adjusted to 20 for realistic scores:
    // - 1 error = ~94%
    // - 5 errors = ~86%
    // - 10 errors = ~79%
    // - 20 errors = ~74%
    // - 50 errors = ~66%
    // - 100 errors = ~60%
    const scalingFactor = 20;
    const logScore = Math.log10(errorCount + 1);
    const score = 100 - (logScore * scalingFactor);

    // Clamp between 0 and 100
    return Math.max(0, Math.min(100, Math.round(score * 10) / 10));
}

/**
 * Alternative: Simple issue density formula (used if preferred)
 * score = 100 / (1 + totalIssues/scalingFactor)
 * Kept for reference but not currently used
 */
function calculateAccuracyScoreSimple(severityBreakdown) {
    const totalIssues = severityBreakdown.ERROR + severityBreakdown.WARNING + severityBreakdown.INFO;

    if (totalIssues === 0) return 100;

    // Scaling factor: 50 issues = ~67%, 100 issues = ~50%
    const scalingFactor = 50;
    const score = 100 / (1 + (totalIssues / scalingFactor));

    return Math.round(score * 10) / 10;
}

/**
 * Get quality category based on accuracy score
 * Thresholds aligned with industry standards
 * 
 * @param {number} score - Accuracy score (0-100)
 * @returns {string} Quality category
 */
function getQualityCategory(score) {
    if (score >= 85) return 'Excellent';   // Very few issues
    if (score >= 65) return 'Good';        // Moderate issues
    if (score >= 45) return 'Fair';        // Many issues
    return 'Needs Improvement';            // Critical issues
}

/**
 * Get color for score visualization
 * @param {number} score - Accuracy score (0-100)
 * @returns {string} Color name
 */
function getScoreColor(score) {
    if (score >= 85) return 'green';
    if (score >= 65) return 'yellow';
    if (score >= 45) return 'orange';
    return 'red';
}

/**
 * Process all report paths and generate statistics
 * @param {Array} reportPaths - Array of relative report paths
 * @returns {Array} Array of report stats objects
 */
function getReportStats(reportPaths) {
    console.log('[reportParser] Processing report paths:', reportPaths);

    if (!reportPaths || reportPaths.length === 0) {
        console.log('[reportParser] No report paths provided');
        return { reports: [], overallAccuracy: 100, overallQuality: 'Excellent', overallColor: 'green' };
    }

    const stats = [];
    let totalErrors = 0;
    let totalWarnings = 0;
    let totalInfo = 0;
    let fileAccuracies = []; // Store individual file accuracies

    reportPaths.forEach((reportPath, index) => {
        try {
            // Construct absolute path (reports are in project root)
            const absolutePath = path.join(__dirname, '..', '..', reportPath);
            console.log(`[reportParser] Absolute path: ${absolutePath}`);

            // Extract filename and language
            const filename = path.basename(reportPath);
            const language = filename
                .replace('_Review.xlsx', '')
                .replace('.xlsx', '');

            // Parse Excel and get findings
            const findings = parseExcelReport(absolutePath);
            console.log(`[reportParser] Parsed ${filename}: ${findings.length} findings`);

            const severityBreakdown = calculateSeverityBreakdown(findings);

            // Calculate accuracy for THIS file
            const fileAccuracy = calculateAccuracyScore(severityBreakdown);
            fileAccuracies.push(fileAccuracy);

            // Accumulate totals for overall severity breakdown display
            totalErrors += severityBreakdown.ERROR;
            totalWarnings += severityBreakdown.WARNING;
            totalInfo += severityBreakdown.INFO;

            const reportStat = {
                index,
                filename,
                language,
                totalFindings: findings.length,
                severityBreakdown
                // Removed individual file accuracyScore, quality, color
            };

            console.log(`[reportParser] Stats for ${filename}: ${findings.length} findings, ${fileAccuracy}% accuracy`);
            stats.push(reportStat);
        } catch (error) {
            console.error(`[reportParser] Error processing report: ${reportPath}`, error);
            // Add placeholder stats for failed reports
            stats.push({
                index,
                filename: path.basename(reportPath),
                language: 'Unknown',
                totalFindings: 0,
                severityBreakdown: { ERROR: 0, WARNING: 0, INFO: 0 },
                error: true
            });
            // Failed files get 0% accuracy
            fileAccuracies.push(0);
        }
    });

    // Calculate overall accuracy as AVERAGE of individual file accuracies
    const overallAccuracy = fileAccuracies.length > 0
        ? Math.round((fileAccuracies.reduce((sum, acc) => sum + acc, 0) / fileAccuracies.length) * 10) / 10
        : 100;

    const overallSeverityBreakdown = {
        ERROR: totalErrors,
        WARNING: totalWarnings,
        INFO: totalInfo
    };
    const overallQuality = getQualityCategory(overallAccuracy);
    const overallColor = getScoreColor(overallAccuracy);

    console.log(`[reportParser] Overall stats - Files: ${fileAccuracies.length}, Average Accuracy: ${overallAccuracy}%`);
    console.log(`[reportParser] Individual file accuracies: [${fileAccuracies.join(', ')}]`);
    console.log(`[reportParser] Total Errors: ${totalErrors}, Warnings: ${totalWarnings}, Info: ${totalInfo}`);

    return {
        reports: stats,
        overallAccuracy,
        overallQuality,
        overallColor,
        overallSeverityBreakdown
    };
}

module.exports = {
    parseExcelReport,
    calculateSeverityBreakdown,
    calculateAccuracyScore,
    getQualityCategory,
    getScoreColor,
    getReportStats
};
