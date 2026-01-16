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

    /**
     * Preview a rule without saving (validation + duplicate check)
     */
    previewRule(description, language, severity = 'WARNING', category = 'security', requestId = 'rule-preview') {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();

            console.log(`[${requestId}] Previewing rule: "${description}" for ${language}`);

            const venvPython = path.join(__dirname, '..', '..', 'venv', 'Scripts', 'python.exe');
            const pythonCmd = fs.existsSync(venvPython) ? venvPython : 'python';

            // Call Python with 'preview' mode
            const pythonProcess = spawn(pythonCmd, [
                this.scriptPath,
                'preview',
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

            const timeoutHandle = setTimeout(() => {
                timedOut = true;
                pythonProcess.kill();
                reject(new Error('Rule preview timed out'));
            }, this.timeout);

            pythonProcess.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            pythonProcess.stderr.on('data', (data) => {
                stderr += data.toString();
                console.log(`[${requestId}] STDERR: ${data.toString().trim()}`);
            });

            pythonProcess.on('close', (code) => {
                clearTimeout(timeoutHandle);

                if (timedOut) return;

                const duration = Date.now() - startTime;
                console.log(`[${requestId}] Preview completed in ${duration}ms with code ${code}`);

                if (code !== 0) {
                    return reject(new Error(`Rule preview failed: ${stderr}`));
                }

                try {
                    // Parse JSON output from Python
                    const result = JSON.parse(stdout);
                    result.duration = duration;
                    resolve(result);
                } catch (parseError) {
                    reject(new Error(`Failed to parse preview result: ${parseError.message}\n${stdout}`));
                }
            });

            pythonProcess.on('error', (error) => {
                clearTimeout(timeoutHandle);
                reject(new Error(`Failed to start Python process: ${error.message}`));
            });
        });
    }

    /**
     * Validate description only (garbage detection)
     */
    validateDescription(description, requestId = 'validate') {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();

            console.log(`[${requestId}] Validating description: "${description.substring(0, 50)}..."`);

            const venvPython = path.join(__dirname, '..', '..', 'venv', 'Scripts', 'python.exe');
            const pythonCmd = fs.existsSync(venvPython) ? venvPython : 'python';

            const pythonProcess = spawn(pythonCmd, [
                this.scriptPath,
                'validate',
                description
            ], {
                cwd: path.join(__dirname, '..', '..'),
                env: { ...process.env }
            });

            let stdout = '';
            let stderr = '';

            const timeoutHandle = setTimeout(() => {
                pythonProcess.kill();
                reject(new Error('Validation timed out'));
            }, 15000); // 15 second timeout for validation

            pythonProcess.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            pythonProcess.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            pythonProcess.on('close', (code) => {
                clearTimeout(timeoutHandle);

                const duration = Date.now() - startTime;

                if (code !== 0) {
                    return reject(new Error(`Validation failed: ${stderr}`));
                }

                try {
                    const result = JSON.parse(stdout);
                    result.duration = duration;
                    resolve(result);
                } catch (parseError) {
                    reject(new Error(`Failed to parse validation result: ${parseError.message}`));
                }
            });

            pythonProcess.on('error', (error) => {
                clearTimeout(timeoutHandle);
                reject(new Error(`Failed to start Python process: ${error.message}`));
            });
        });
    }

    /**
     * Save a previewed rule to file
     */
    async confirmRule(ruleData, language, requestId = 'confirm') {
        return new Promise((resolve, reject) => {
            console.log(`[${requestId}] Confirming and saving rule to ${language}-rules.yml`);

            const rulesDir = path.join(__dirname, '..', '..', 'rules');
            const ruleFile = path.join(rulesDir, `${language.toLowerCase()}-rules.yml`);

            try {
                // Ensure rules directory exists
                if (!fs.existsSync(rulesDir)) {
                    fs.mkdirSync(rulesDir, { recursive: true });
                }

                // Read existing file or create new
                let existingContent = '';
                if (fs.existsSync(ruleFile)) {
                    existingContent = fs.readFileSync(ruleFile, 'utf-8');
                } else {
                    existingContent = 'rules:\n';
                }

                // Append new rule
                const yaml = require('js-yaml');
                let ruleYaml = yaml.dump([ruleData], { noRefs: true, sortKeys: false });

                // Remove leading "- " and indent properly
                if (ruleYaml.startsWith('- ')) {
                    ruleYaml = ruleYaml.substring(2);
                }
                const indentedRule = ruleYaml.split('\n')
                    .map(line => line ? '  ' + line : line)
                    .join('\n');

                // Ensure proper spacing
                if (!existingContent.endsWith('\n')) {
                    existingContent += '\n';
                }

                const newContent = existingContent + '\n  # AI-Generated Rule\n  - ' + indentedRule.trim() + '\n';

                // Write to file
                fs.writeFileSync(ruleFile, newContent, 'utf-8');

                console.log(`[${requestId}] Rule saved successfully to ${ruleFile}`);

                resolve({
                    success: true,
                    filePath: `rules/${language.toLowerCase()}-rules.yml`,
                    message: 'Rule saved successfully'
                });

            } catch (error) {
                reject(new Error(`Failed to save rule: ${error.message}`));
            }
        });
    }
}

module.exports = new RuleGenerator();
