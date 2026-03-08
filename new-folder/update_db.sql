-- Run this to add new tables for new components
USE SOAR1;

-- Notification log table (for Notification Service component)
CREATE TABLE IF NOT EXISTS notification_log (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    alert_id        INT,
    severity        ENUM('CRITICAL','HIGH','MEDIUM','LOW'),
    type            VARCHAR(255),
    notify_roles    VARCHAR(255),
    risk_score      INT,
    recommendation  TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Threat intel log table (for Threat Intelligence component)
CREATE TABLE IF NOT EXISTS threat_intel_log (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    alert_id        INT,
    threat_category VARCHAR(255),
    risk_score      INT,
    has_malicious_ip TINYINT(1) DEFAULT 0,
    ip_reputation   TEXT,
    recommendation  TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

SELECT 'New tables created successfully!' AS Result;
