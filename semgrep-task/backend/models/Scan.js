const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

const Scan = sequelize.define('Scan', {
    id: {
        type: DataTypes.STRING(255),
        primaryKey: true,
    },
    userId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
            model: 'users',
            key: 'id',
        },
        onDelete: 'CASCADE',
    },
    type: {
        type: DataTypes.ENUM('github', 'upload'),
        allowNull: false,
    },
    input: {
        type: DataTypes.TEXT,
        allowNull: true,
        comment: 'GitHub URL or uploaded file name',
    },
    status: {
        type: DataTypes.ENUM('pending', 'running', 'completed', 'failed'),
        defaultValue: 'pending',
    },
    reportPaths: {
        type: DataTypes.JSON,
        defaultValue: [],
        comment: 'Array of report file paths',
    },
    reportCount: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
    },
    error: {
        type: DataTypes.TEXT,
        allowNull: true,
    },
    duration: {
        type: DataTypes.INTEGER,
        allowNull: true,
        comment: 'Scan duration in milliseconds',
    },
    completedAt: {
        type: DataTypes.DATE,
        allowNull: true,
    },
    failedAt: {
        type: DataTypes.DATE,
        allowNull: true,
    },
}, {
    timestamps: true,
    tableName: 'scans',
    indexes: [
        {
            name: 'idx_userId_createdAt',
            fields: ['userId', 'createdAt'],
        },
        {
            name: 'idx_status',
            fields: ['status'],
        },
    ],
});

// Instance methods
Scan.prototype.markCompleted = async function (reportPaths, duration) {
    this.status = 'completed';
    this.reportPaths = reportPaths || [];
    this.reportCount = reportPaths ? reportPaths.length : 0;
    this.duration = duration;
    this.completedAt = new Date();
    await this.save();
};

Scan.prototype.markFailed = async function (error) {
    this.status = 'failed';
    this.error = error;
    this.failedAt = new Date();
    await this.save();
};

Scan.prototype.markRunning = async function () {
    this.status = 'running';
    await this.save();
};

module.exports = Scan;
