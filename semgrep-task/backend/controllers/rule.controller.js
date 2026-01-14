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
