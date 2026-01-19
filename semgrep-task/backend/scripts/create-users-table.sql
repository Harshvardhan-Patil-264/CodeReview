-- SQL Schema for Users Table
-- Execute this in MySQL command line or workbench

-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS code_review_db;
USE code_review_db;

-- Drop existing users table if you want to recreate it
-- DROP TABLE IF EXISTS users;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NULL,
    authProvider ENUM('local', 'google', 'github') DEFAULT 'local',
    githubAccessToken VARCHAR(255) NULL,
    createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Verify table structure
DESCRIBE users;

-- Check if table is empty
SELECT COUNT(*) as total_users FROM users;
