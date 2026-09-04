<?php
/**
 * CORS CSP Lab · legacy.hackinlab.internal
 *
 * The weak host inside the *.hackinlab.internal wildcard used by level 5.
 * It is a small internal status page that nobody has touched in years, and it
 * prints the note parameter straight into the document.
 *
 * There is no Content-Security-Policy here on purpose: the point of level 5 is
 * that the CORS allowlist inherits this host's weaknesses, whatever they are.
 */

$note = (string)($_GET['note'] ?? '');
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Legacy status board</title>
<link rel="stylesheet" href="css/frame.css">
</head>
<body class="frame">
<h1>hackinlab.internal &mdash; legacy status board</h1>
<p class="muted">Host: legacy.hackinlab.internal &middot; no CSP configured &middot; retired 2019, still routed</p>

<div class="card">
    <h2>Operator note</h2>
    <!-- The sink: $note goes into the document with no escaping at all. -->
    <div id="note"><?= $note ?></div>
</div>

<div class="card">
    <h2>Services</h2>
    <ul>
        <li>billing-api &mdash; ok</li>
        <li>portal &mdash; ok</li>
        <li>legacy-status &mdash; ok</li>
    </ul>
</div>
</body>
</html>
