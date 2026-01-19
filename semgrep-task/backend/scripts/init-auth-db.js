const { sequelize, testConnection } = require('../config/db');
const User = require('../models/User');

async function initializeDatabase() {
    try {
        console.log('🔄 Initializing database...');

        // Test connection
        await testConnection();

        // Create database if it doesn't exist
        await sequelize.query(`CREATE DATABASE IF NOT EXISTS ${process.env.DB_NAME || 'code_review_db'}`);
        console.log(`✅ Database "${process.env.DB_NAME || 'code_review_db'}" ready`);

        // Sync models (create tables)
        await sequelize.sync({ alter: true }); // Use 'alter: true' to update existing tables
        console.log('✅ Database tables synchronized');

        console.log('\n📋 Database Schema:');
        const [tables] = await sequelize.query('SHOW TABLES');
        tables.forEach((table) => {
            console.log(`  - ${Object.values(table)[0]}`);
        });

        console.log('\n✅ Database initialization complete!\n');
    } catch (error) {
        console.error('❌ Database initialization failed:', error.message);
        throw error;
    }
}

// Run if called directly
if (require.main === module) {
    initializeDatabase()
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
}

module.exports = { initializeDatabase };
