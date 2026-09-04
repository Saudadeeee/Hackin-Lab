<?php
/**
 * The redirect, performed for real.
 *
 * The level pages run each level's filter and then *model* what a browser would
 * do with the value, because a genuine 302 would navigate you away from the page
 * before you could read the trace or the flag. That is useful for learning and
 * it leaves one honest question unanswered: does the vulnerable line actually
 * emit the header its source panel shows?
 *
 * This endpoint answers it. It runs the same `redirect_level_filter()` the level
 * runs, and when the filter accepts, it really does call:
 *
 *     header('Location: ' . $target);
 *
 * Confirm it from a terminal, where nothing follows the redirect for you:
 *
 *     curl -i "http://localhost:8092/go.php?level=1&next=https://evil.attacker.example"
 *
 * No flag is awarded here. This is the proof, not the challenge.
 */
require_once __DIR__ . '/helpers.php';

$level = (int)($_GET['level'] ?? 0);
$next  = (string)($_GET['next'] ?? ($_POST['next'] ?? ''));

if ($level < 1 || $level > 10) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo "usage: go.php?level=<1-10>&next=<url>\n";
    exit;
}

$verdict = redirect_level_filter($level, $next);

if (empty($verdict['allowed'])) {
    // Fail the way the level does: the filter rejected the value, so no
    // Location header is emitted at all.
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo "level $level filter REJECTED the value, so no redirect is issued.\n";
    echo "reason: " . ($verdict['reason'] ?? '') . "\n";
    exit;
}

// The vulnerable line, exactly as the source panel shows it.
header('Location: ' . $verdict['target']);
http_response_code(302);

// A body, so a browser that does follow the redirect still leaves a trace and
// a curl without -L has something to read.
header('Content-Type: text/plain; charset=utf-8');
echo "302 issued by level $level\n";
echo "Location: " . $verdict['target'] . "\n";
