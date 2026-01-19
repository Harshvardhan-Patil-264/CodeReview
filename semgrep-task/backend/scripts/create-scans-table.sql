-- Create scans table for storing scan history
-- This table links scans to users and stores scan metadata and report paths

CREATE TABLE IF NOT EXISTS scans (
    id VARCHAR(255) PRIMARY KEY,
    userId CHAR(36) NOT NULL,
    type ENUM('github', 'upload') NOT NULL,
    input TEXT COMMENT 'GitHub URL or uploaded file name',
    status ENUM('pending', 'running', 'completed', 'failed') DEFAULT 'pending',
    reportPaths JSON COMMENT 'Array of report file paths',
    reportCount INT DEFAULT 0,
    error TEXT,
    duration INT COMMENT 'Scan duration in milliseconds',
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    completedAt DATETIME,
    failedAt DATETIME,
    
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_userId_createdAt (userId, createdAt DESC),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
