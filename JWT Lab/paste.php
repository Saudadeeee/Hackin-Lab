<?php
/**
 * A deliberately boring "host some JSON at a URL" service.
 *
 * It exists so level 8 can be about the jku allowlist rather than about
 * standing up a web server. Nothing here is the vulnerability.
 */
require_once __DIR__ . '/lab_kit.php';

$dir = __DIR__ . '/pastes';
if (!is_dir($dir)) {
    @mkdir($dir, 0777, true);
}

/* Serve a stored paste as JSON. */
if (isset($_GET['id'])) {
    $id   = preg_replace('/[^a-f0-9]/', '', (string)$_GET['id']);
    $file = $dir . '/' . $id . '.json';
    header('Content-Type: application/json');
    if ($id === '' || !is_file($file)) {
        http_response_code(404);
        echo json_encode(['error' => 'not found']);
        exit;
    }
    readfile($file);
    exit;
}

$saved = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body = (string)($_POST['content'] ?? '');
    if (strlen($body) > 20000) {
        $saved = '<div class="message error">Too large.</div>';
    } elseif (trim($body) === '') {
        $saved = '<div class="message error">Nothing to store.</div>';
    } else {
        $id = bin2hex(random_bytes(8));
        file_put_contents($dir . '/' . $id . '.json', $body);
        $browserUrl = 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost:8093') . '/paste.php?id=' . $id;
        $serverUrl  = 'http://localhost/paste.php?id=' . $id;
        $saved = '<div class="message success">Stored.<br>'
               . '<strong>From your browser:</strong> <code>' . lk_esc($browserUrl) . '</code><br>'
               . '<strong>From the server (use this one in <code>jku</code>):</strong> <code>' . lk_esc($serverUrl) . '</code>'
               . '<br><span class="text-muted">The verifier fetches from inside the container, where the published host '
               . 'port does not exist - so a URL with <code>:8093</code> in it will time out. '
               . 'Content-Type is <code>application/json</code>, so a JWKS fetcher will accept the body.</span></div>';
    }
}
?><!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Paste — JWT Lab</title><link rel="stylesheet" href="css/styles.css"></head>
<body>
<header class="header">
    <div class="header-left"><h1>Paste</h1><p>Host arbitrary JSON on this origin</p></div>
    <div class="header-right"><a href="tools.php" class="back-btn">&larr; Workbench</a></div>
</header>
<div class="container submit-container">
    <div class="scenario">Store a JSON document and get a URL back. Used by the <code>jku</code> level so you have
    somewhere to publish a key set you control.</div>
    <?= $saved ?>
    <form method="post" class="flag-form">
        <div class="form-group">
            <label class="form-label">JSON content</label>
            <textarea name="content" rows="12" class="form-control" spellcheck="false"
                      style="font-family:'JetBrains Mono',monospace;font-size:0.78rem"><?= lk_esc($_POST['content'] ?? '') ?></textarea>
        </div>
        <button class="btn btn-primary" type="submit">Store</button>
    </form>
</div>
</body>
</html>
