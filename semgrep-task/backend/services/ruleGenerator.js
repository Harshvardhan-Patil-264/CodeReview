const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

class RuleGenerator {
    constructor() {
        this.scriptPath = path.join(__dirname, '..', '..', 'rule-generator.py');
        this.timeout = 60000; // 60 seconds for AI generation
    }

    generateRule(description, language, severity = 'WARNING', category = 'security', requestId = 'rule-gen') {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();

            console.log(`[${requestId}] Generating rule: "${description}" for ${language}`);

            // Use same Python as scanning
            const venvPython = path.join(__dirname, '..', '..', 'venv', 'Scripts', 'python.exe');
            const pythonCmd = fs.existsSync(venvPython) ? venvPython : 'python';

            // Spawn Python process with arguments
            const pythonProcess = spawn(pythonCmd, [
                this.scriptPath,
                description,
                language,
                severity,
                category
            ], {
                cwd: path.join(__dirname, '..', '..'),
                env: { ...process.env }
            });

            let stdout = '';
            let stderr = '';
            let timedOut = false;

            // Set timeout
            const timeoutHandle = setTimeout(() => {
                timedOut = true;
                pythonProcess.kill();
                reject(new Error('Rule generation timed out'));
            }, this.timeout);

            // Capture stdout
            pythonProcess.stdout.on('data', (data) => {
                stdout += data.toString();
                console.log(`[${requestId}] STDOUT: ${data.toString().trim()}`);
            });

            // Capture stderr
            pythonProcess.stderr.on('data', (data) => {
                stderr += data.toString();
                console.log(`[${requestId}] STDERR: ${data.toString().trim()}`);
            });

            // Handle process completion
            pythonProcess.on('close', (code) => {
                clearTimeout(timeoutHandle);

                if (timedOut) {
                    return; // Already rejected
                }

                const duration = Date.now() - startTime;
                console.log(`[${requestId}] Process completed in ${duration}ms with code ${code}`);

                if (code !== 0) {
                    return reject(new Error(`Rule generation failed with code ${code}: ${stderr}`));
                }

                // Parse output to find generated rule file
                const filePathMatch = stdout.match(/Saved to:\s*([^\r\n]+)/);
                const filePath = filePathMatch ? filePathMatch[1].trim() : null;

                // Try to extract YAML from output
                const yamlStart = stdout.indexOf('rules:');
                const generatedYaml = yamlStart >= 0 ? stdout.substring(yamlStart) : null;

                resolve({
                    success: true,
                    stdout: stdout,
                    stderr: stderr,
                    filePath: filePath,
                    yaml: generatedYaml,
                    duration: duration
                });
            });

            pythonProcess.on('error', (error) => {
                clearTimeout(timeoutHandle);
                reject(new Error(`Failed to start Python process: ${error.message}`));
            });
        });
    }
}

module.exports = new RuleGenerator();
