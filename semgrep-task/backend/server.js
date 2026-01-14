const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const scanRoutes = require('./routes/scan.routes');
const ruleRoutes = require('./routes/rule.routes');
const errorHandler = require('./middleware/errorHandler');
const logger = require('./middleware/logger');

const app = express();
const PORT = process.env.PORT || 5000;

// Create required directories
const dirs = ['logs', 'uploads', 'reports'];
dirs.forEach(dir => {
    const dirPath = path.join(__dirname, dir);
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
    }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(logger);

// Routes
app.use('/api', scanRoutes);
app.use('/api/rules', ruleRoutes);

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Error handling (must be last)
app.use(errorHandler);

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Backend server running on http://localhost:${PORT}`);
    console.log(`📁 Working directory: ${__dirname}`);
    console.log(`🐍 Python engine path: ${path.join(__dirname, '..', 'auto-review.py')}`);
});

module.exports = app;
