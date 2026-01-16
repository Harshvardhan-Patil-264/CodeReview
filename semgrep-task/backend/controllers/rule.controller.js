const ruleGenerator = require('../services/ruleGenerator');

exports.generateRule = async (req, res, next) => {
    try {
        const { description, language, severity, category } = req.body;

        // Validation
        if (!description || !description.trim()) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_REQUEST',
                    message: 'Rule description is required'
                }
            });
        }

        if (!language || !language.trim()) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_REQUEST',
                    message: 'Language is required'
                }
            });
        }

        const validLanguages = ['python', 'javascript', 'java', 'go'];
        if (!validLanguages.includes(language.toLowerCase())) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_REQUEST',
                    message: `Language must be one of: ${validLanguages.join(', ')}`
                }
            });
        }

        console.log(`[${req.requestId}] Rule generation request:`, {
            description: description.substring(0, 50) + '...',
            language,
            severity: severity || 'WARNING',
            category: category || 'security'
        });

        // Generate rule
        const result = await ruleGenerator.generateRule(
            description,
            language.toLowerCase(),
            severity || 'WARNING',
            category || 'security',
            req.requestId
        );

        console.log(`[${req.requestId}] Rule generated successfully: ${result.filePath}`);

        res.json({
            success: true,
            message: 'Rule generated successfully',
            filePath: result.filePath,
            yaml: result.yaml,
            duration: result.duration
        });

    } catch (error) {
        console.error(`[${req.requestId}] Rule generation error:`, error);
        next(error);
    }
};

/**
 * POST /api/rules/preview
 * Preview a rule without saving (includes validation and duplicate check)
 */
exports.previewRule = async (req, res, next) => {
    try {
        const { description, language, severity, category } = req.body;

        // Validation
        if (!description || !description.trim()) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_REQUEST',
                    message: 'Rule description is required'
                }
            });
        }

        if (!language || !language.trim()) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_REQUEST',
                    message: 'Language is required'
                }
            });
        }

        const validLanguages = ['python', 'javascript', 'java', 'go'];
        if (!validLanguages.includes(language.toLowerCase())) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_REQUEST',
                    message: `Language must be one of: ${validLanguages.join(', ')}`
                }
            });
        }

        console.log(`[${req.requestId}] Rule preview request:`, {
            description: description.substring(0, 50) + '...',
            language,
            severity: severity || 'WARNING',
            category: category || 'security'
        });

        // Preview rule (no saving)
        const result = await ruleGenerator.previewRule(
            description,
            language.toLowerCase(),
            severity || 'WARNING',
            category || 'security',
            req.requestId
        );

        console.log(`[${req.requestId}] Rule preview completed`);
        console.log(`[${req.requestId}] Validation: ${result.validation?.is_valid ? 'VALID' : 'INVALID'} (score: ${result.validation?.quality_score})`);
        console.log(`[${req.requestId}] Duplicates: ${result.duplicates?.has_duplicates ? 'YES' : 'NO'}`);

        res.json({
            success: true,
            message: 'Rule preview generated',
            rule: result.rule,
            yaml: result.yaml,
            validation: result.validation,
            duplicates: result.duplicates,
            duration: result.duration
        });

    } catch (error) {
        console.error(`[${req.requestId}] Rule preview error:`, error);
        next(error);
    }
};

/**
 * POST /api/rules/validate
 * Validate a description (garbage detection)
 */
exports.validateDescription = async (req, res, next) => {
    try {
        const { description } = req.body;

        if (!description || !description.trim()) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_REQUEST',
                    message: 'Description is required'
                }
            });
        }

        console.log(`[${req.requestId}] Validating description: "${description.substring(0, 50)}..."`);

        const validation = await ruleGenerator.validateDescription(
            description,
            req.requestId
        );

        console.log(`[${req.requestId}] Validation result: ${validation.is_valid ? 'VALID' : 'INVALID'} (score: ${validation.quality_score})`);

        res.json({
            success: true,
            validation: validation
        });

    } catch (error) {
        console.error(`[${req.requestId}] Validation error:`, error);
        next(error);
    }
};

/**
 * POST /api/rules/confirm
 * Save a previewed rule to file
 */
exports.confirmRule = async (req, res, next) => {
    try {
        const { rule, language } = req.body;

        // Validation
        if (!rule || typeof rule !== 'object') {
            return res.status(400).json({
                error: {
                    code: 'INVALID_REQUEST',
                    message: 'Rule data is required'
                }
            });
        }

        if (!language || !language.trim()) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_REQUEST',
                    message: 'Language is required'
                }
            });
        }

        console.log(`[${req.requestId}] Confirming and saving rule: ${rule.id}`);

        const result = await ruleGenerator.confirmRule(
            rule,
            language.toLowerCase(),
            req.requestId
        );

        console.log(`[${req.requestId}] Rule saved successfully to ${result.filePath}`);

        res.json({
            success: true,
            message: result.message,
            filePath: result.filePath
        });

    } catch (error) {
        console.error(`[${req.requestId}] Rule confirmation error:`, error);
        next(error);
    }
};
