<?php
/**
 * CORS CSP Lab · the page the CSP levels inject into.
 *
 * This file sends the real Content-Security-Policy header for the level and
 * then renders the attacker-controlled markup without escaping it. Nothing is
 * simulated: whatever your browser does inside this frame is the browser
 * enforcing that header.
 *
 *   render.php?level=6&i=<markup>       levels 6, 7, 8, 10
 *   render.php?level=9&t=<template>     level 9 (the template, not markup)
 */

require_once __DIR__ . '/helpers.php';

$level    = (int)($_GET['level'] ?? 6);
$injected = (string)($_GET['i'] ?? '');
$template = (string)($_GET['t'] ?? '');

if ($level < 6 || $level > 10) {
    http_response_code(404);
    exit('This frame only serves levels 6 to 10.');
}

/* The nonce, built exactly the way the level's source panel says it is. */
$nonce = '';
if ($level === 7) {
    $nonce = bp_daily_nonce();          // mt_rand() seeded with a day counter
} elseif ($level === 8 || $level === 10) {
    $nonce = bp_random_nonce();         // 9 bytes from the CSPRNG, per response
}

$policy = bp_policy($level, $nonce);
header('Content-Security-Policy: ' . $policy);
header('Cache-Control: no-store');
$n = $nonce !== '' ? ' nonce="' . htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') . '"' : '';
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Storefront widget frame &mdash; level <?= $level ?></title>
<link rel="stylesheet" href="css/frame.css">
<!-- hlab.win() lives here. It is loaded before anything else so that a payload
     which manages to run always has something to call. -->
<script<?= $n ?> src="frame.js"></script>
<?php if ($level === 8): ?>
<!-- Theme fragment, pasted into the head from the page's own settings.
     This is the injection point for level 8. -->
<?= $injected ?>
<?php endif; ?>
<?php if ($level === 9): ?>
<script<?= $n ?> src="tmpl.js"></script>
<?php endif; ?>
<?php if ($level === 10): ?>
<script<?= $n ?> src="loader.js"></script>
<?php endif; ?>
</head>
<body class="frame">

<h1>Storefront widget</h1>
<p class="muted">
    level <?= $level ?> &middot; policy sent with this response:<br>
    <code><?= htmlspecialchars($policy, ENT_QUOTES, 'UTF-8') ?></code>
</p>

<div class="card">
    <h2>Product notes</h2>
    <?php if ($level === 9): ?>
        <!-- tmpl.js reads the template out of the query string and renders here. -->
        <div id="out" class="muted">rendering template&hellip;</div>
    <?php elseif ($level === 8): ?>
        <div class="muted">The theme fragment above was written into the document head.</div>
    <?php else: ?>
        <!-- The injection point: the note is written into the document as HTML. -->
        <div id="note"><?= $injected ?></div>
    <?php endif; ?>
</div>

<div id="hlab-status" class="status">no script has called hlab.win() yet</div>

<?php if ($level === 8): ?>
<!-- The page's own widget, loaded by a RELATIVE path. The nonce is an
     attribute of this element; it says nothing about where the URL points. -->
<script<?= $n ?> src="app/widget.js"></script>
<?php endif; ?>
</body>
</html>
