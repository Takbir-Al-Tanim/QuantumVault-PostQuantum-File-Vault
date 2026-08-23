USE pq_file_vault;

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

ALTER TABLE performance_logs
MODIFY COLUMN operation ENUM('upload','download','benchmark','share_create','shared_download') NOT NULL;
