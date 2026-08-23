CREATE DATABASE IF NOT EXISTS pq_file_vault
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE pq_file_vault;

CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    email VARCHAR(190) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    mlkem_public_key MEDIUMBLOB NOT NULL,
    mlkem_secret_key_enc MEDIUMBLOB NOT NULL,
    mlkem_secret_key_nonce VARBINARY(12) NOT NULL,
    key_algorithm VARCHAR(32) NOT NULL DEFAULT 'ML-KEM-768',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS folders (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    owner_id BIGINT UNSIGNED NOT NULL,
    parent_id BIGINT UNSIGNED NULL,
    name VARCHAR(120) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_folders_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_folders_parent FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE,
    INDEX idx_folders_owner_parent (owner_id, parent_id),
    INDEX idx_folders_owner_name (owner_id, name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS files (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    file_uuid CHAR(36) NOT NULL UNIQUE,
    owner_id BIGINT UNSIGNED NOT NULL,
    folder_id BIGINT UNSIGNED NULL,
    original_filename VARCHAR(255) NOT NULL,
    encrypted_filename VARCHAR(100) NOT NULL UNIQUE,
    file_type VARCHAR(30) NOT NULL,
    original_size BIGINT UNSIGNED NOT NULL,
    encrypted_size BIGINT UNSIGNED NOT NULL,
    mlkem_ciphertext MEDIUMBLOB NOT NULL,
    hkdf_salt VARBINARY(16) NOT NULL,
    chacha_nonce VARBINARY(12) NOT NULL,
    kem_algorithm VARCHAR(32) NOT NULL DEFAULT 'ML-KEM-768',
    kdf_algorithm VARCHAR(32) NOT NULL DEFAULT 'HKDF-SHA256',
    encryption_algorithm VARCHAR(40) NOT NULL DEFAULT 'ChaCha20-Poly1305',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_files_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_files_folder FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL,
    INDEX idx_files_owner_created (owner_id, created_at),
    INDEX idx_files_owner_folder (owner_id, folder_id),
    INDEX idx_files_owner_name (owner_id, original_filename)
) ENGINE=InnoDB;


CREATE TABLE IF NOT EXISTS file_shares (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    file_id BIGINT UNSIGNED NOT NULL,
    owner_id BIGINT UNSIGNED NOT NULL,
    recipient_id BIGINT UNSIGNED NOT NULL,
    mlkem_ciphertext MEDIUMBLOB NOT NULL,
    hkdf_salt VARBINARY(16) NOT NULL,
    wrap_nonce VARBINARY(12) NOT NULL,
    wrapped_file_key VARBINARY(80) NOT NULL,
    permission VARCHAR(30) NOT NULL DEFAULT 'download',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_share_file FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
    CONSTRAINT fk_share_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_share_recipient FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT uq_file_recipient UNIQUE (file_id, recipient_id),
    INDEX idx_share_recipient_created (recipient_id, created_at),
    INDEX idx_share_owner_created (owner_id, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS performance_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    file_id BIGINT UNSIGNED NULL,
    operation ENUM('upload','download','benchmark','share_create','shared_download') NOT NULL,
    benchmark_label VARCHAR(120) NULL,
    file_type VARCHAR(30) NULL,
    file_size_bytes BIGINT UNSIGNED NOT NULL,
    ciphertext_size_bytes BIGINT UNSIGNED NULL,
    mlkem_keygen_ms DECIMAL(12,4) NULL,
    mlkem_encap_ms DECIMAL(12,4) NULL,
    mlkem_decap_ms DECIMAL(12,4) NULL,
    hkdf_ms DECIMAL(12,4) NULL,
    encrypt_ms DECIMAL(12,4) NULL,
    decrypt_ms DECIMAL(12,4) NULL,
    total_ms DECIMAL(12,4) NOT NULL,
    throughput_mbps DECIMAL(14,4) NULL,
    peak_memory_kb DECIMAL(14,2) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_perf_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_perf_file FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL,
    INDEX idx_perf_user_created (user_id, created_at),
    INDEX idx_perf_operation (operation)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NULL,
    action VARCHAR(60) NOT NULL,
    target_type VARCHAR(30) NULL,
    target_id VARCHAR(80) NULL,
    detail VARCHAR(500) NULL,
    ip_address VARCHAR(45) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_audit_user_created (user_id, created_at)
) ENGINE=InnoDB;
