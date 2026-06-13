-- Legitimate Database Schema
-- Standard SQL for application database

CREATE TABLE IF NOT EXISTS users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id INT PRIMARY KEY AUTO_INCREMENT,
    case_id VARCHAR(50) NOT NULL UNIQUE,
    user_id INT NOT NULL,
    target VARCHAR(500) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    verdict VARCHAR(50) NOT NULL,
    risk_score FLOAT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_verdict (verdict),
    INDEX idx_created (created_at)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id INT PRIMARY KEY AUTO_INCREMENT,
    scan_id INT NOT NULL,
    finding_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    message TEXT,
    line_number INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    INDEX idx_severity (severity)
);

CREATE TABLE IF NOT EXISTS api_logs (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    api_name VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    response_time_ms INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_api (api_name),
    INDEX idx_status (status)
);

-- Create indexes for better query performance
CREATE INDEX idx_scans_user_date ON scans(user_id, created_at);
CREATE INDEX idx_findings_scan ON findings(scan_id);

-- Insert default admin user (password should be changed)
INSERT INTO users (username, email, password_hash) VALUES
('admin', 'admin@forensic-scanner.local', 'hashed_password_here');
