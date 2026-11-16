-- Development schema only. Apply to an isolated test database before migration.
CREATE TABLE vv_auth_guard (id TINYINT PRIMARY KEY) ENGINE=InnoDB;
INSERT INTO vv_auth_guard VALUES (1);
CREATE TABLE vv_auth_users (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 username VARCHAR(64) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL UNIQUE,
 role ENUM('technical','operational','user') NOT NULL,
 technical_slot TINYINT AS (CASE WHEN role='technical' THEN 1 ELSE NULL END) PERSISTENT UNIQUE,
 password_hash VARCHAR(255) NOT NULL,
 recovery_digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 active BOOLEAN NOT NULL DEFAULT TRUE,
 must_change BOOLEAN NOT NULL DEFAULT FALSE,
 epoch BIGINT UNSIGNED NOT NULL DEFAULT 0,
 CHECK (role <> 'technical' OR (active=1 AND recovery_digest IS NOT NULL))
) ENGINE=InnoDB;
CREATE TABLE vv_auth_sessions (
 digest CHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 user_id BIGINT UNSIGNED NOT NULL,
 epoch BIGINT UNSIGNED NOT NULL,
 expires_at DATETIME NOT NULL,
 INDEX(user_id), INDEX(expires_at),
 FOREIGN KEY(user_id) REFERENCES vv_auth_users(id)
) ENGINE=InnoDB;
CREATE TABLE vv_auth_limits (
 scope VARCHAR(100) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 attempts INT UNSIGNED NOT NULL DEFAULT 0,
 window_start DATETIME NOT NULL
) ENGINE=InnoDB;
CREATE TABLE vv_auth_audit (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 actor_id BIGINT UNSIGNED NULL,
 target_id BIGINT UNSIGNED NULL,
 action VARCHAR(40) NOT NULL,
 occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
