-- ================================================
-- SOAR Database Setup Script
-- Run this ONCE to create the database and table
-- ================================================

CREATE DATABASE IF NOT EXISTS SOAR1;
USE SOAR1;

CREATE TABLE IF NOT EXISTS alerts (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    source      VARCHAR(255)    NOT NULL,
    type        VARCHAR(255)    NOT NULL,
    severity    ENUM('CRITICAL','HIGH','MEDIUM','LOW') NOT NULL,
    message     TEXT,
    status      ENUM('OPEN','IN_PROGRESS','RESOLVED','CLOSED') DEFAULT 'OPEN',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Optional: insert a test alert to verify setup
INSERT INTO alerts (source, type, severity, message, status)
VALUES ('Test', 'Setup Verification', 'LOW', 'Database setup successful', 'RESOLVED');

SELECT 'SOAR1 database setup complete!' AS Result;
