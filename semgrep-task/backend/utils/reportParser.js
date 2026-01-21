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
 * Calculate accuracy score based on severity breakdown
 * 
 * Uses a weighted scoring system with diminishing returns (logarithmic scale)
 * Similar to industry-standard tools like SonarQube, CodeClimate
 * 
 * Approach:
 * 1. Assign severity weights: ERROR=10, WARNING=3, INFO=1
 * 2. Calculate total weighted issues
 * 3. Use logarithmic scale to prevent harsh penalties
 * 4. Scale to 0-100 range
 * 
 * This gives more realistic scores:
 * - 0 issues = 100% (Perfect)
 * - 5 errors = ~82% (Good)
 * - 10 errors + 20 warnings = ~67% (Fair)
 * - 50 errors + 100 warnings = ~33% (Needs Improvement)
 * - 100+ errors = <20% (Critical)
 * 
 * @param {Object} severityBreakdown - { ERROR: 0, WARNING: 0, INFO: 0 }
 * @returns {number} Accuracy score (0-100)
 */
function calculateAccuracyScore(severityBreakdown) {
    // Severity weights (industry standard)
    const WEIGHTS = {
        ERROR: 10,    // Critical issues
        WARNING: 3,   // Important but not critical
        INFO: 1       // Minor suggestions
    };

    // Calculate total weighted score
    const weightedScore =
        (severityBreakdown.ERROR * WEIGHTS.ERROR) +
        (severityBreakdown.WARNING * WEIGHTS.WARNING) +
        (severityBreakdown.INFO * WEIGHTS.INFO);

    // If no issues, perfect score
    if (weightedScore === 0) {
        return 100;
    }

    // Logarithmic scale with diminishing returns
    // This prevents extremely harsh penalties for high issue counts
    // Formula: 100 - (log10(weightedScore + 1) * scalingFactor)
    // Scaling factor adjusted to 15 for more realistic scores:
    // - 100 weighted points (~10 errors) = ~70%
    // - 200 weighted points (~20 errors) = ~65%
    // - 500 weighted points (~50 errors) = ~60%
    // - 1000+ weighted points = declining to 0%
    const scalingFactor = 15;
    const logScore = Math.log10(weightedScore + 1);
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
        return [];
    }

    const stats = [];

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
            const accuracyScore = calculateAccuracyScore(severityBreakdown);
            const quality = getQualityCategory(accuracyScore);
            const color = getScoreColor(accuracyScore);

            const reportStat = {
                index,
                filename,
                language,
                totalFindings: findings.length,
                severityBreakdown,
                accuracyScore,
                quality,
                color
            };

            console.log(`[reportParser] Stats for ${filename}:`, reportStat);
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
                accuracyScore: 0,
                quality: 'Unknown',
                color: 'gray',
                error: true
            });
        }
    });

    console.log(`[reportParser] Returning ${stats.length} report stats`);
    return stats;
}

module.exports = {
    parseExcelReport,
    calculateSeverityBreakdown,
    calculateAccuracyScore,
    getQualityCategory,
    getScoreColor,
    getReportStats
};
