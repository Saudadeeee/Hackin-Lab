CREATE DATABASE IF NOT EXISTS sqli_lab;
USE sqli_lab;

-- Bảng người dùng cơ bản
CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(50)
);
INSERT INTO users (username) VALUES ('alice'),('bob');

-- Thêm nhiều user ngẫu nhiên để làm nhiễu
INSERT INTO users (username) VALUES 
  ('admin'),('root'),('test'),('guest'),('user123'),('demo'),
  ('flag_hunter'),('security'),('hacker'),('pentester'),('student'),
  ('teacher'),('manager'),('developer'),('tester'),('analyst'),
  ('charlie'),('david'),('emma'),('frank'),('grace'),('henry'),
  ('isabel'),('jack'),('kate'),('lucas'),('mary'),('nick'),
  ('oliver'),('paul'),('queen'),('robert'),('sarah'),('tom');

-- Bảng chứa flag cho các cấp độ
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

-- Bảng hỗ trợ second-order injection
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

-- Thêm cột password cho authentication bypass
ALTER TABLE users ADD COLUMN password VARCHAR(100) DEFAULT 'password123';
UPDATE users SET password = 'admin123' WHERE username = 'admin';

-- Thêm metadata cho các level mới
INSERT INTO meta (mkey, mvalue) VALUES
  ('level8_hint', 'Try XPATH functions like extractvalue()'),
  ('level9_hint', 'Sometimes OR 1=1 is all you need'),
  ('level10_hint', 'INSERT can be dangerous too'),
  ('level11_hint', 'UPDATE statements can leak data'),
  ('level12_hint', 'WAFs can be bypassed with encoding'),
  ('level13_hint', 'JSON parsing can introduce vulnerabilities');

-- Thêm chỉ mục để tối ưu hóa hiệu suất
CREATE INDEX idx_username ON users(username);
CREATE INDEX idx_level_id ON levels(id);
CREATE INDEX idx_meta_key ON meta(mkey);

-- Thêm bảng logs để theo dõi các attempt
CREATE TABLE access_logs (
  id INT PRIMARY KEY AUTO_INCREMENT,
  ip_address VARCHAR(45),
  user_agent TEXT,
  query_attempted TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  level_accessed INT,
  success BOOLEAN DEFAULT FALSE
);

-- Tạo user riêng cho ứng dụng web sau khi tất cả bảng đã sẵn sàng
DROP USER IF EXISTS 'webapp'@'%';
CREATE USER 'webapp'@'%' IDENTIFIED BY 'webapp123';
GRANT SELECT, INSERT, UPDATE, DELETE ON sqli_lab.* TO 'webapp'@'%';
FLUSH PRIVILEGES;

-- Thêm một số dữ liệu test để verify database hoạt động
INSERT INTO access_logs (ip_address, user_agent, query_attempted, level_accessed, success) VALUES
  ('127.0.0.1', 'MySQL Init Script', 'Database initialization completed', 0, TRUE);