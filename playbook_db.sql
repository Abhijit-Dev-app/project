USE SOAR1;

CREATE TABLE IF NOT EXISTS playbooks (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(255) NOT NULL,
    description   TEXT,
    severity      ENUM('CRITICAL','HIGH','MEDIUM','LOW','ANY') NOT NULL DEFAULT 'ANY',
    trigger_type  VARCHAR(255) DEFAULT '',   -- keyword to match in alert type
    actions       TEXT NOT NULL,             -- JSON array of actions
    is_active     TINYINT(1) DEFAULT 1,
    created_by    VARCHAR(100),
    updated_by    VARCHAR(100),
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS playbook_executions (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    playbook_id   INT NOT NULL,
    playbook_name VARCHAR(255),
    alert_id      INT,
    alert_type    VARCHAR(255),
    severity      VARCHAR(50),
    actions_taken TEXT,       
    status        ENUM('SUCCESS','FAILED','PARTIAL') DEFAULT 'SUCCESS',
    executed_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO playbooks (name, description, severity, trigger_type, actions, created_by) VALUES
('Brute Force Response',      'Block IP and notify admin on brute force attacks',         'CRITICAL', 'brute force',         '["BLOCK_IP","NOTIFY_ADMIN","CREATE_TICKET"]',      'system'),
('Unauthorized Access',       'Block IP and notify admin on unauthorized access',         'CRITICAL', 'unauthorized access',  '["BLOCK_IP","NOTIFY_ADMIN","CREATE_TICKET"]',      'system'),
('Malware Containment',       'Isolate host immediately on malware detection',            'CRITICAL', 'malware',             '["ISOLATE_HOST","NOTIFY_ADMIN","CREATE_TICKET"]',  'system'),
('Ransomware Response',       'Immediate host isolation on ransomware activity',          'CRITICAL', 'ransomware',          '["ISOLATE_HOST","NOTIFY_ADMIN","CREATE_TICKET"]',  'system'),
('Port Scan Detection',       'Block scanning IP and log the event',                      'HIGH',     'port scan',           '["BLOCK_IP","LOG_ONLY"]',                         'system'),
('Reconnaissance Alert',      'Block and log reconnaissance activity',                    'HIGH',     'reconnaissance',      '["BLOCK_IP","LOG_ONLY"]',                         'system'),
('High Severity Generic',     'Isolate host on any unclassified high severity alert',     'HIGH',     '',                    '["ISOLATE_HOST","LOG_ONLY"]',                     'system'),
('Medium Severity Response',  'Log and notify analyst on medium severity alerts',         'MEDIUM',   '',                    '["LOG_ONLY","NOTIFY_ANALYST"]',                   'system'),
('Low Severity Logging',      'Log only for low severity events',                         'LOW',      '',                    '["LOG_ONLY"]',                                    'system');

SELECT 'Playbook tables created and seeded!' AS Result;
