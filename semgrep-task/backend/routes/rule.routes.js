const express = require('express');
const router = express.Router();
const ruleController = require('../controllers/rule.controller');

// Generate new rule (original endpoint - generates and saves immediately)
router.post('/generate', ruleController.generateRule);

// Preview rule (new endpoint - generates with validation but doesn't save)
router.post('/preview', ruleController.previewRule);

// Validate description only (new endpoint - garbage detection)
router.post('/validate', ruleController.validateDescription);

// Confirm and save previewed rule (new endpoint - saves to file)
router.post('/confirm', ruleController.confirmRule);

module.exports = router;
