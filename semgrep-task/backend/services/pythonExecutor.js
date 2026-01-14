const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

// Timeout for Python execution (5 minutes)
const EXECUTION_TIMEOUT = 5 * 60 * 1000;

/**
 * Execute Python script with security measures
 * Uses spawn instead of exec to prevent command injection
 */
class PythonExecutor {
    constructor() {
        this.enginePath = path.join(__dirname, '..', '..', 'auto-review.py');

        // Verify Python engine exists
        if (!fs.existsSync(this.enginePath)) {
            throw new Error(`Python engine not found at: ${this.enginePath}`);
        }
    }

    /**
     * Execute scan with timeout and sanitized arguments
     * @param {string} targetPath - Path to scan (GitHub URL or local directory)
     * @param {string} requestId - Request ID for logging
     * @returns {Promise<object>} - Execution result
     */
    async executeScan(targetPath, requestId) {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();

            // Use Python from venv to ensure Semgrep is available
            const venvPython = path.join(__dirname, '..', '..', 'venv', 'Scripts', 'python.exe');
            const pythonCmd = fs.existsSync(venvPython) ? venvPython : 'python';

            // Add Semgrep Scripts directory to PATH (use Python314 which has working Semgrep)
            const semgrepPath = path.join(process.env.USERPROFILE, 'AppData', 'Local', 'Programs', 'Python', 'Python314', 'Scripts');
            const enhancedEnv = { ...process.env };
            enhancedEnv.PATH = `${semgrepPath}${path.delimiter}${enhancedEnv.PATH}`;

            console.log(`[${requestId}] Using Python: ${pythonCmd}`);
            console.log(`[${requestId}] Command: ${pythonCmd} ${this.enginePath} "${targetPath}"`);

            // Spawn Python process with sanitized arguments
            // Using array prevents command injection
            const pythonProcess = spawn(pythonCmd, [this.enginePath, targetPath], {
                cwd: path.join(__dirname, '..', '..'), // Set working directory
                env: enhancedEnv // Enhanced environment with Semgrep in PATH
            });

            let stdout = '';
            let stderr = '';
            let timedOut = false;

            // Set execution timeout
            const timeout = setTimeout(() => {
                timedOut = true;
                pythonProcess.kill('SIGTERM');
                console.log(`[${requestId}] Process killed due to timeout`);
            }, EXECUTION_TIMEOUT);

            // Capture stdout
            pythonProcess.stdout.on('data', (data) => {
                const output = data.toString();
                stdout += output;
                console.log(`[${requestId}] STDOUT:`, output.trim());
            });

            // Capture stderr
            pythonProcess.stderr.on('data', (data) => {
                const output = data.toString();
                stderr += output;
                console.error(`[${requestId}] STDERR:`, output.trim());
            });

            // Handle process completion
            pythonProcess.on('close', (code) => {
                clearTimeout(timeout);
                const duration = Date.now() - startTime;

                console.log(`[${requestId}] Process completed in ${duration}ms with code ${code}`);

                if (timedOut) {
                    return reject({
                        success: false,
                        error: 'Scan execution timed out (exceeded 5 minutes)',
                        code: 'TIMEOUT',
                        status: 408
                    });
                }

                if (code !== 0) {
                    return reject({
                        success: false,
                        error: `Python execution failed with code ${code}`,
                        details: stderr || stdout,
                        code: 'EXECUTION_FAILED',
                        status: 500
                    });
                }

                // Parse output to find ALL generated reports
                const reportRegex = /(?:Created new report|Updated report)\s*:\s*([^\n]+)/g;
                const reportMatches = [...stdout.matchAll(reportRegex)];
                const reportPaths = reportMatches.map(match => match[1].trim());

                resolve({
                    success: true,
                    stdout: stdout,
                    stderr: stderr,
                    reportPaths: reportPaths, // Now an array of all reports
                    reportCount: reportPaths.length,
                    duration: duration
                });
            });

            // Handle process errors
            pythonProcess.on('error', (error) => {
                clearTimeout(timeout);
                console.error(`[${requestId}] Process error:`, error);

                reject({
                    success: false,
                    error: `Failed to start Python process: ${error.message}`,
                    code: 'PROCESS_ERROR',
                    status: 500
                });
            });
        });
    }
}

module.exports = new PythonExecutor();
