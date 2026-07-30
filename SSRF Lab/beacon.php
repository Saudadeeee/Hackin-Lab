<?php
/**
 * beacon.php — INTERNAL blind-SSRF beacon (loopback only).
 *
 * Records every hit it receives to beacon_hits.log and returns the level-3
 * flag in the body. In the blind-SSRF level the attacker never sees this body;
 * the app confirms the internal service was reached entirely server-side.
 */
require_once __DIR__ . '/helpers.php';

header('Content-Type: text/plain; charset=utf-8');

$remote = $_SERVER['REMOTE_ADDR'] ?? '';
$isLoopback = in_array($remote, ['127.0.0.1', '::1'], true) || strncmp($remote, '127.', 4) === 0;

if (!$isLoopback) {
    http_response_code(403);
    echo "403 Forbidden — internal beacon, loopback only. From: {$remote}\n";
    exit;
}

// Record the hit (this is what a real blind-SSRF beacon does).
$logFile = __DIR__ . '/beacon_hits.log';
$entry = date('Y-m-d H:i:s') . " | hit from {$remote} | level=" . (int)($_GET['level'] ?? 3) . "\n";
@file_put_contents($logFile, $entry, FILE_APPEND);

echo "beacon-ok\n";
echo get_flag_for_level(3) . "\n";
