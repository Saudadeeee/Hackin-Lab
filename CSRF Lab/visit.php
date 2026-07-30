<?php
/**
 * visit.php — the "victim admin" bot.
 *
 * A logged-in admin opens the attacker's page. This endpoint takes the
 * learner's crafted PoC and performs the request it describes AS the admin
 * (the server attaches the admin session), then records the outcome and
 * redirects back to the level page (Post/Redirect/Get).
 *
 * Also usable directly:  visit.php?level=1&poc=<img src="change_email.php?email=x">
 */

require_once __DIR__ . '/helpers.php';

$level = (int)($_POST['level'] ?? $_GET['level'] ?? 0);
$poc   = (string)($_POST['poc']  ?? $_GET['poc']  ?? '');

if ($level < 1 || $level > 10) {
    header('Location: index.php');
    exit;
}

$result        = csrf_deliver($level, $poc);
$result['poc'] = $poc;

if (!isset($_SESSION['csrf_result']) || !is_array($_SESSION['csrf_result'])) {
    $_SESSION['csrf_result'] = [];
}
$_SESSION['csrf_result'][$level] = $result;

header('Location: level' . $level . '.php', true, 303);
exit;
