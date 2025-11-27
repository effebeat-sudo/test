CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user','admin','superuser') NOT NULL DEFAULT 'user',
    otp_hash VARCHAR(255) NULL,
    otp_expires_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cards (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    notes TEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE card_entries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    card_id INT NOT NULL,
    login VARCHAR(255) NOT NULL,
    password_encrypted TEXT NOT NULL,
    url VARCHAR(500) NULL,
    FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE
);

-- Crea un superuser iniziale (aggiorna email/password se necessario)
INSERT INTO users (email, password_hash, role)
VALUES ('superuser@example.com', '$2y$12$dC53jXKtEiFLNNibSCrxMu4MQSYYbu6Sh4JOG43CI3FZRQce7b0IG', 'superuser');
