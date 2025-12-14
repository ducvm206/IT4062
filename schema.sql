-- MySQL Database Schema for P2P File Sharing System
-- Database: p2p_db

-- =========================
-- TABLE: accounts
-- =========================
CREATE TABLE IF NOT EXISTS accounts (
    account_id     INT AUTO_INCREMENT PRIMARY KEY,
    username       VARCHAR(64) NOT NULL UNIQUE,
    password_hash  VARCHAR(65) NOT NULL,           -- SHA-256 hex
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================
-- TABLE: clients
-- =========================
CREATE TABLE IF NOT EXISTS clients (
    client_id   INT UNSIGNED PRIMARY KEY,         -- uint32 stored as INT UNSIGNED
    account_id  INT NOT NULL,
    ip_address  VARCHAR(15) NOT NULL,
    port        INT NOT NULL,
    last_seen   DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================
-- TABLE: files
-- =========================
CREATE TABLE IF NOT EXISTS files (
    file_id       INT AUTO_INCREMENT PRIMARY KEY,
    client_id     INT UNSIGNED NOT NULL,
    filename      VARCHAR(255) NOT NULL,
    filesize      BIGINT NOT NULL,
    published_at  DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (client_id)
        REFERENCES clients(client_id)
        ON DELETE CASCADE,
    INDEX idx_files_filename (filename)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;