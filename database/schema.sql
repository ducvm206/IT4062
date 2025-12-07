PRAGMA foreign_keys = ON;

-- =========================
-- TABLE: accounts
-- =========================
CREATE TABLE IF NOT EXISTS accounts (
    account_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,           -- SHA-256 hex
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =========================
-- TABLE: clients
-- =========================
CREATE TABLE IF NOT EXISTS clients (
    client_id   INTEGER PRIMARY KEY,         -- uint32 stored as INTEGER
    account_id  INTEGER NOT NULL,
    ip_address  TEXT NOT NULL,
    port        INTEGER NOT NULL,
    last_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (account_id)
        REFERENCES accounts(account_id)
        ON DELETE CASCADE
);

-- =========================
-- TABLE: files
-- =========================
CREATE TABLE IF NOT EXISTS files (
    file_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     INTEGER NOT NULL,
    filename      TEXT NOT NULL,
    filesize      INTEGER NOT NULL,
    published_at  DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (client_id)
        REFERENCES clients(client_id)
        ON DELETE CASCADE
);

-- =========================
-- INDEXES
-- =========================
CREATE INDEX IF NOT EXISTS idx_files_filename
    ON files(filename);