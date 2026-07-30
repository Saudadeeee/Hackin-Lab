<?php
/**
 * internal.php — INTERNAL-ONLY flag endpoint.
 *
 * This page returns a level flag ONLY when the request originates from the
 * loopback interface (127.0.0.1 / ::1). A normal browser request comes from a
 * non-loopback address and is refused with 403. The only way to read the flag
 * is to make the *server* fetch this page for you — i.e. a successful SSRF.
 *
 * It intentionally serves flags for the levels whose lesson is "reach the
 * generic internal service": 1, 4, 5, 7, 9, 10.
 */
require_once __DIR__ . '/helpers.php';

header('Content-Type: text/plain; charset=utf-8');

$remote = $_SERVER['REMOTE_ADDR'] ?? '';

// Only loopback source addresses are trusted as "internal".
$isLoopback = in_array($remote, ['127.0.0.1', '::1'], true) || strncmp($remote, '127.', 4) === 0;

if (!$isLoopback) {
    http_response_code(403);
    echo "403 Forbidden\n";
    echo "internal.php is restricted to the loopback interface.\n";
    echo "Your request originated from: {$remote}\n";
    exit;
}

$level = (int)($_GET['level'] ?? 0);
$servedLevels = [1, 4, 5, 7, 9, 10];

echo "===== INTERNAL SERVICE (loopback only) =====\n";
echo "Request source: {$remote} (trusted)\n";
echo "Requested level: {$level}\n";
echo "--------------------------------------------\n";

if (in_array($level, $servedLevels, true)) {
    echo "Access granted. Level {$level} secret:\n";
    echo get_flag_for_level($level) . "\n";
} else {
    echo "No internal secret is exposed here for level {$level}.\n";
    echo "This endpoint answers levels: " . implode(', ', $servedLevels) . "\n";
}
