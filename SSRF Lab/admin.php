<?php
/**
 * admin.php — INTERNAL admin / status panel (loopback only).
 *
 * Simulates a private management interface that is bound to the loopback
 * interface. It renders its status dashboard (with the level-2 flag) only when
 * the request comes from 127.0.0.1 / ::1. Reachable via SSRF, never directly.
 */
require_once __DIR__ . '/helpers.php';

$remote = $_SERVER['REMOTE_ADDR'] ?? '';
$isLoopback = in_array($remote, ['127.0.0.1', '::1'], true) || strncmp($remote, '127.', 4) === 0;

if (!$isLoopback) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo "403 Forbidden\n";
    echo "admin.php (internal management panel) accepts loopback requests only.\n";
    echo "Your request originated from: {$remote}\n";
    exit;
}

header('Content-Type: text/plain; charset=utf-8');
$flag = get_flag_for_level(2);
?>
=====================================================
   INTERNAL ADMIN PANEL  ·  status: OK
   (bound to 127.0.0.1 — not exposed publicly)
=====================================================
service        : ssrf-lab-web
uptime         : 4d 07h 12m
build          : 8.2-apache
workers        : 8 / 8 healthy
queue depth    : 0
admin_token    : <?= $flag ?>

-----------------------------------------------------
Only the server itself should ever see this page.
If you are reading this through the app's fetcher,
you just performed Server-Side Request Forgery.
=====================================================
