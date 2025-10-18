CREATE DATABASE IF NOT EXISTS sqli_lab;
USE sqli_lab;

CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(50) UNIQUE,
  password VARCHAR(100) DEFAULT 'password123',
  email VARCHAR(100) DEFAULT '',
  role VARCHAR(20) DEFAULT 'user',
  phone VARCHAR(30) DEFAULT '',
  bio TEXT,
  website VARCHAR(200) DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password, email, role) VALUES
  ('alice', 'alicepass', 'alice@example.com', 'user'),
  ('bob', 'bobpass', 'bob@example.com', 'user'),
  ('admin', 'adminpass', 'admin@example.com', 'admin'),
  ('root', 'rootpass', 'root@example.com', 'user'),
  ('test', 'testpass', 'test@example.com', 'user'),
  ('guest', 'guestpass', 'guest@example.com', 'user'),
  ('user123', 'password123', 'user123@example.com', 'user'),
  ('demo', 'password123', 'demo@example.com', 'user'),
  ('flag_hunter', 'password123', 'flag_hunter@example.com', 'user'),
  ('security', 'password123', 'security@example.com', 'user'),
  ('hacker', 'password123', 'hacker@example.com', 'user'),
  ('pentester', 'password123', 'pentester@example.com', 'user'),
  ('student', 'password123', 'student@example.com', 'user'),
  ('teacher', 'password123', 'teacher@example.com', 'user'),
  ('manager', 'password123', 'manager@example.com', 'user'),
  ('developer', 'password123', 'developer@example.com', 'user'),
  ('tester', 'password123', 'tester@example.com', 'user'),
  ('analyst', 'password123', 'analyst@example.com', 'user'),
  ('charlie', 'password123', 'charlie@example.com', 'user'),
  ('david', 'password123', 'david@example.com', 'user'),
  ('emma', 'password123', 'emma@example.com', 'user'),
  ('frank', 'password123', 'frank@example.com', 'user'),
  ('grace', 'password123', 'grace@example.com', 'user'),
  ('henry', 'password123', 'henry@example.com', 'user'),
  ('isabel', 'password123', 'isabel@example.com', 'user'),
  ('jack', 'password123', 'jack@example.com', 'user'),
  ('kate', 'password123', 'kate@example.com', 'user'),
  ('lucas', 'password123', 'lucas@example.com', 'user'),
  ('mary', 'password123', 'mary@example.com', 'user'),
  ('nick', 'password123', 'nick@example.com', 'user'),
  ('oliver', 'password123', 'oliver@example.com', 'user'),
  ('paul', 'password123', 'paul@example.com', 'user'),
  ('queen', 'password123', 'queen@example.com', 'user'),
  ('robert', 'password123', 'robert@example.com', 'user'),
  ('sarah', 'password123', 'sarah@example.com', 'user'),
  ('tom', 'password123', 'tom@example.com', 'user');

UPDATE users SET password = 'admin123', role = 'admin' WHERE username = 'admin';

CREATE TABLE levels (
  id INT PRIMARY KEY,
  flag VARCHAR(100)
);

INSERT INTO levels (id, flag) VALUES
  (1,'FLAG{error_based}'),
  (2,'FLAG{union_based}'),
  (3,'FLAG{stacked_queries}'),
  (4,'FLAG{boolean_blind}'),
  (5,'FLAG{time_based}'),
  (6,'FLAG{oob_file_write}'),
  (7,'FLAG{second_order}'),
  (8,'FLAG{xpath_injection}'),
  (9,'FLAG{auth_bypass_success}'),
  (10,'FLAG{insert_injection}'),
  (11,'FLAG{update_injection}'),
  (12,'FLAG{waf_bypass}'),
  (13,'FLAG{json_injection}'),
  (14,'FLAG{comment_bypass}'),
  (15,'FLAG{encoding_bypass}'),
  (16,'FLAG{space_bypass}'),
  (21,'FAKE{not_a_real_flag}'),
  (22,'TEST{dummy_flag_123}'),
  (23,'DECOY{red_herring}'),
  (24,'SAMPLE{example_only}'),
  (25,'DEMO{practice_flag}'),
  (26,'NULL'),
  (27,''),
  (28,'FLAG{fake_sql_injection}'),
  (29,'CTF{wrong_competition}'),
  (30,'HINT{keep_looking}'),
  (31,'RABBIT{hole_ahead}'),
  (32,'WARNING{trap_detected}'),
  (33,'ERROR{invalid_flag}');

CREATE TABLE meta (
  id INT PRIMARY KEY AUTO_INCREMENT,
  mkey VARCHAR(50),
  mvalue TEXT
);

INSERT INTO meta (mkey, mvalue) VALUES
  ('config_version', '1.2.3'),
  ('db_charset', 'utf8mb4'),
  ('max_connections', '100'),
  ('timeout', '30'),
  ('debug_mode', 'false'),
  ('log_level', 'info'),
  ('cache_enabled', 'true'),
  ('session_timeout', '3600'),
  ('encryption_key', 'abc123def456'),
  ('api_version', 'v2.1'),
  ('flag_hint', 'Look deeper in the right table'),
  ('fake_flag', 'FLAG{this_is_not_real}'),
  ('admin_note', 'Remember to change default passwords'),
  ('backup_location', '/var/backups/'),
  ('last_update', '2023-12-01'),
  ('maintenance_mode', 'off'),
  ('feature_flags', 'experimental_enabled'),
  ('rate_limit', '1000'),
  ('ssl_enabled', 'true'),
  ('cors_origin', '*'),
  ('jwt_secret', 'secret_key_here'),
  ('database_url', 'mysql://localhost:3306'),
  ('redis_host', '127.0.0.1'),
  ('smtp_server', 'mail.example.com'),
  ('file_upload_path', '/uploads/'),
  ('temp_directory', '/tmp/'),
  ('log_file', '/var/log/app.log'),
  ('pid_file', '/var/run/app.pid'),
  ('lock_file', '/var/lock/app.lock'),
  ('secret_message', 'The real treasure was the friends we made along the way');

-- Additional metadata for level-specific hints
INSERT INTO meta (mkey, mvalue) VALUES
  ('level8_hint', 'Try XPATH functions like extractvalue()'),
  ('level9_hint', 'Sometimes OR 1=1 is all you need'),
  ('level10_hint', 'INSERT can be dangerous too'),
  ('level11_hint', 'UPDATE statements can leak data'),
  ('level12_hint', 'WAFs can be bypassed with encoding'),
  ('level13_hint', 'JSON parsing can introduce vulnerabilities'),
  ('level14_hint', 'Comments can break up blocked keywords'),
  ('level15_hint', 'Try different encoding methods'),
  ('level16_hint', 'Spaces are not the only whitespace');

-- Helpful indexes for performance
CREATE INDEX idx_username ON users(username);
CREATE INDEX idx_level_id ON levels(id);
CREATE INDEX idx_meta_key ON meta(mkey);

-- Access logs for monitoring attempts
CREATE TABLE access_logs (
  id INT PRIMARY KEY AUTO_INCREMENT,
  ip_address VARCHAR(45),
  user_agent TEXT,
  query_attempted TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  level_accessed INT,
  success BOOLEAN DEFAULT FALSE
);

-- Seed access log with baseline record
INSERT INTO access_logs (ip_address, user_agent, query_attempted, level_accessed, success) VALUES
  ('127.0.0.1', 'MySQL Init Script', 'Database initialization completed', 0, TRUE);

-- Application database users with scoped privileges
DROP USER IF EXISTS 'webapp'@'%';
CREATE USER 'webapp'@'%' IDENTIFIED BY 'webapp123';
GRANT SELECT, INSERT, UPDATE, DELETE ON sqli_lab.users TO 'webapp'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON sqli_lab.meta TO 'webapp'@'%';
GRANT SELECT, INSERT, UPDATE ON sqli_lab.access_logs TO 'webapp'@'%';

DROP USER IF EXISTS 'flagchecker'@'%';
CREATE USER 'flagchecker'@'%' IDENTIFIED BY 'flagchecker123';
GRANT SELECT ON sqli_lab.levels TO 'flagchecker'@'%';

FLUSH PRIVILEGES;
