USE SOAR1;

-- Main tickets table
CREATE TABLE IF NOT EXISTS tickets (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    ticket_ref    VARCHAR(20) NOT NULL UNIQUE,  -- e.g. TKT-0001
    alert_id      INT,
    title         VARCHAR(255) NOT NULL,
    description   TEXT,
    priority      ENUM('CRITICAL','HIGH','MEDIUM','LOW') NOT NULL DEFAULT 'MEDIUM',
    status        ENUM('OPEN','IN_PROGRESS','PENDING','RESOLVED','CLOSED') DEFAULT 'OPEN',
    assigned_to   VARCHAR(100),                 -- username of analyst
    created_by    VARCHAR(100),
    resolved_at   TIMESTAMP NULL,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Ticket timeline / activity log
CREATE TABLE IF NOT EXISTS ticket_timeline (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id   INT NOT NULL,
    action      VARCHAR(100) NOT NULL,   -- e.g. STATUS_CHANGE, COMMENT, ASSIGNED
    detail      TEXT,                    -- what changed or comment text
    performed_by VARCHAR(100),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Ticket comments
CREATE TABLE IF NOT EXISTS ticket_comments (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id   INT NOT NULL,
    comment     TEXT NOT NULL,
    author      VARCHAR(100),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Auto-increment counter for ticket reference numbers
CREATE TABLE IF NOT EXISTS ticket_counter (
    id      INT AUTO_INCREMENT PRIMARY KEY,
    counter INT DEFAULT 0
);

INSERT INTO ticket_counter (counter) VALUES (0);

SELECT 'Ticket tables created!' AS Result;
