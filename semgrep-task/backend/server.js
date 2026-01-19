const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const scanRoutes = require('./routes/scan.routes');
const ruleRoutes = require('./routes/rule.routes');
const authRoutes = require('./routes/auth.routes');
const errorHandler = require('./middleware/errorHandler');
const logger = require('./middleware/logger');
const { sequelize, testConnection } = require('./config/db');
const { cleanupOrphanedScans } = require('./services/cleanupService');

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
app.use('/api/auth', authRoutes);

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

// Initialize database and start server
async function startServer() {
    try {
        // Test database connection
        await testConnection();

        // Sync Sequelize models (create tables if they don't exist)
        const User = require('./models/User');
        const Scan = require('./models/Scan');

        // Define associations
        User.hasMany(Scan, {
            foreignKey: 'userId',
            as: 'scans',
            onDelete: 'CASCADE',
        });

        Scan.belongsTo(User, {
            foreignKey: 'userId',
            as: 'user',
        });

        // Sync database models
        await sequelize.sync();
        console.log('✅ Database models synced');

        // Clean up orphaned scans from previous server runs
        await cleanupOrphanedScans();

        // Start server
        app.listen(PORT, () => {
            console.log(`🚀 Backend server running on http://localhost:${PORT}`);
            console.log(`📁 Working directory: ${__dirname}`);
            console.log(`🐍 Python engine path: ${path.join(__dirname, '..', 'auto-review.py')}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error.message);
        process.exit(1);
    }
}

startServer();

module.exports = app;
