const { sequelize } = require('../config/db');
const User = require('../models/User');
const Scan = require('../models/Scan');

/**
 * Initialize scans database
 * This script creates the scans table and sets up relationships
 */

async function initScansDB() {
    try {
        console.log('🔄 Initializing scans database...');

        // Test database connection
        await sequelize.authenticate();
        console.log('✅ Database connection established');

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

        // Sync Scan model (create table if not exists)
        await Scan.sync({ alter: false });
        console.log('✅ Scans table created/verified');

        console.log('✅ Scans database initialized successfully');
        process.exit(0);

    } catch (error) {
        console.error('❌ Failed to initialize scans database:', error);
        process.exit(1);
    }
}

initScansDB();
