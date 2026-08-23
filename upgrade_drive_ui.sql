USE pq_file_vault;

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

SET @folder_col_exists = (
    SELECT COUNT(*)
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'files'
      AND COLUMN_NAME = 'folder_id'
);

SET @sql = IF(
    @folder_col_exists = 0,
    'ALTER TABLE files ADD COLUMN folder_id BIGINT UNSIGNED NULL AFTER owner_id',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @folder_index_exists = (
    SELECT COUNT(*)
    FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'files'
      AND INDEX_NAME = 'idx_files_owner_folder'
);
SET @sql = IF(
    @folder_index_exists = 0,
    'ALTER TABLE files ADD INDEX idx_files_owner_folder (owner_id, folder_id)',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @folder_fk_exists = (
    SELECT COUNT(*)
    FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME = 'files'
      AND CONSTRAINT_NAME = 'fk_files_folder'
);
SET @sql = IF(
    @folder_fk_exists = 0,
    'ALTER TABLE files ADD CONSTRAINT fk_files_folder FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Keep secure sharing available even if upgrading from an older pre-sharing database.
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
