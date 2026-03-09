<?php
$dbPath = '/var/db/idor_lab.db';
$pdo = new PDO('sqlite:' . $dbPath);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Drop and recreate all tables
$pdo->exec("DROP TABLE IF EXISTS users");
$pdo->exec("DROP TABLE IF EXISTS documents");
$pdo->exec("DROP TABLE IF EXISTS orders");
$pdo->exec("DROP TABLE IF EXISTS uploads");
$pdo->exec("DROP TABLE IF EXISTS password_resets");
$pdo->exec("DROP TABLE IF EXISTS tokens");
$pdo->exec("DROP TABLE IF EXISTS api_keys");
$pdo->exec("DROP TABLE IF EXISTS messages");
$pdo->exec("DROP TABLE IF EXISTS rewards");

// Users table
$pdo->exec("CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    api_key TEXT,
    reset_token TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");

// Documents table
$pdo->exec("CREATE TABLE documents (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    is_private INTEGER DEFAULT 1
)");

// Orders table
$pdo->exec("CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    items TEXT NOT NULL,
    total REAL NOT NULL,
    status TEXT DEFAULT 'pending'
)");

// Uploads table
$pdo->exec("CREATE TABLE uploads (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    content TEXT NOT NULL
)");

// Messages table
$pdo->exec("CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");

// Rewards table (for level 10 race condition)
$pdo->exec("CREATE TABLE rewards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    claimed INTEGER DEFAULT 0,
    claimed_by INTEGER DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");

// Seed users
$users = [
    [1, 'alice', 'alice123', 'alice@lab.local', 'user', 'key_alice_abc123', md5('alice')],
    [2, 'bob', 'bob456', 'bob@lab.local', 'user', 'key_bob_def456', md5('bob')],
    [3, 'charlie', 'charlie789', 'charlie@lab.local', 'user', 'key_charlie_ghi', md5('charlie')],
    [4, 'admin', 'supersecret', 'admin@lab.local', 'admin', 'key_admin_MASTER', md5('admin')],
    [5, 'guest', 'guest', 'guest@lab.local', 'user', 'key_guest_xyz', md5('guest')],
];
$stmt = $pdo->prepare("INSERT INTO users (id, username, password, email, role, api_key, reset_token) VALUES (?,?,?,?,?,?,?)");
foreach ($users as $u) $stmt->execute($u);

// Seed documents
$docs = [
    [1, 1, 'Alice Personal Notes', 'My private diary... nothing here', 1],
    [2, 2, 'Bob Budget 2024', 'Bob private expenses data', 1],
    [3, 3, 'Charlie Project Plan', 'Confidential project roadmap', 1],
    [4, 4, 'Admin Secret Config', 'FLAG{basic_idor_object_reference} - admin only internal config', 1],
    [5, 1, 'Alice Public Blog', 'This is a public post!', 0],
];
$stmt = $pdo->prepare("INSERT INTO documents (id, owner_id, title, content, is_private) VALUES (?,?,?,?,?)");
foreach ($docs as $d) $stmt->execute($d);

// Seed orders
$orders = [
    [1, 1, 'Coffee x2', 8.00, 'completed'],
    [2, 2, 'Laptop Stand', 45.00, 'pending'],
    [3, 3, 'Keyboard x1', 120.00, 'shipped'],
    [4, 4, 'Admin Equipment', 9999.00, 'pending'],
    [5, 5, 'Guest Trial', 0.01, 'completed'],
];
$stmt = $pdo->prepare("INSERT INTO orders (id, user_id, items, total, status) VALUES (?,?,?,?,?)");
foreach ($orders as $o) $stmt->execute($o);

// Seed uploads
$uploads = [
    [1, 1, 'alice_doc.txt', 'personal_notes.txt', 'Alice personal upload content'],
    [2, 2, 'bob_report.txt', 'quarterly_report.txt', 'FLAG{idor_file_download} - CONFIDENTIAL: Q4 profit report'],
    [3, 3, 'charlie_plan.txt', 'project_plan.txt', 'Charlie project planning document'],
    [4, 4, 'admin_keys.txt', 'admin_credentials.txt', 'ADMIN ONLY - backup credentials'],
    [5, 5, 'guest_sample.txt', 'sample.txt', 'Guest sample file content'],
];
$stmt = $pdo->prepare("INSERT INTO uploads (id, owner_id, filename, original_name, content) VALUES (?,?,?,?,?)");
foreach ($uploads as $u) $stmt->execute($u);

// Seed messages
$messages = [
    [1, 4, 1, 'Welcome', 'Welcome to the system, alice!', '2024-01-01'],
    [2, 4, 2, 'Security Alert', 'FLAG{horizontal_privilege_escalation} - Bob, your account had suspicious activity', '2024-01-02'],
    [3, 1, 2, 'Hello Bob', 'Hi Bob, shall we meet?', '2024-01-03'],
    [4, 4, 4, 'Admin Note', 'Admin private note to self: system is secure', '2024-01-04'],
];
$stmt = $pdo->prepare("INSERT INTO messages (id, sender_id, recipient_id, subject, body, created_at) VALUES (?,?,?,?,?,?)");
foreach ($messages as $m) $stmt->execute($m);

echo "Database initialized successfully.\n";
