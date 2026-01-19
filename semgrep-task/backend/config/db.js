const { Sequelize } = require('sequelize');
require('dotenv').config();

const sequelize = new Sequelize(
    process.env.DB_NAME || 'code_review_db',
    process.env.DB_USER || 'root',
    process.env.DB_PASSWORD || 'pass',
    {
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 3306,
        dialect: 'mysql',
        logging: false, // Set to console.log to see SQL queries
        pool: {
            max: 5,
            min: 0,
            acquire: 30000,
            idle: 10000,
        },
    }
);

// Test database connection
async function testConnection() {
    try {
        await sequelize.authenticate();
        console.log(' Database connection established successfully');
    } catch (error) {
        console.error(' Unable to connect to database:', error.message);
        throw error;
    }
}

module.exports = { sequelize, testConnection };
