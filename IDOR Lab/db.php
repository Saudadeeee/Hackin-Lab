<?php
function get_db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dbPath = '/var/db/idor_lab.db';
        if (!file_exists($dbPath)) {
            require_once __DIR__ . '/init_db.php';
        }
        $pdo = new PDO('sqlite:' . $dbPath, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }
    return $pdo;
}
