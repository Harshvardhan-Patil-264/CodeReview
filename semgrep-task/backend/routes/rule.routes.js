const express = require('express');
const router = express.Router();
const ruleController = require('../controllers/rule.controller');

// Generate new rule
router.post('/generate', ruleController.generateRule);

module.exports = router;
