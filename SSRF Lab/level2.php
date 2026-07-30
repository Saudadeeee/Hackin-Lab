<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 2;
$levelTitle = 'Internal Service Access';
$prevLevel  = 1;
$nextLevel  = 3;

// ── Challenge logic ──────────────────────────────────────────
$url = $_GET['url'] ?? '';

$flag        = '';
$flagMessage = '';
$response    = '';
$fetchError  = '';

if ($url !== '') {
    // Still no validation — but now the interesting target is a private
    // management interface that refuses non-loopback callers.
    $ctx = stream_context_create(['http' => ['timeout' => 4, 'ignore_errors' => true]]);
    $response = @file_get_contents($url, false, $ctx);
    if ($response === false) {
        $response   = '';
        $fetchError = 'The request failed (host unreachable, timed out, or refused).';
    }
    if (ssrf_captured($levelId, $response)) {
        $flag        = get_flag_for_level($levelId);
        $flagMessage = 'You proxied through the server into the loopback-only admin panel.';
    }
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 2 — Internal Service Access | SSRF Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x1F310;</span> SSRF Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">

    <div class="level-header">
        <span class="level-badge">Level 2</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-easy">Easy</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-variable">$url</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'url'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// The fetcher happily proxies to internal services too</span>
<span class="php-variable">$ctx</span> = stream_context_create([<span class="php-string">'http'</span> =&gt; [<span class="php-string">'timeout'</span> =&gt; <span class="php-string">4</span>]]);
<span class="vuln-line"><span class="php-variable">$response</span> = file_get_contents(<span class="php-variable">$url</span>, <span class="php-keyword">false</span>, <span class="php-variable">$ctx</span>);</span>
<span class="php-keyword">echo</span> <span class="php-variable">$response</span>;

<span class="php-comment">// admin.php refuses REMOTE_ADDR != loopback (403),</span>
<span class="php-comment">// but the SERVER's own request comes from 127.0.0.1.</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The internal <code>admin.php</code> trusts the
                loopback interface for authentication. Because the vulnerable fetcher runs
                <em>on the server</em>, its request to <code>admin.php</code> originates from
                <code>127.0.0.1</code> and is treated as a trusted, authenticated admin.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The app runs a private admin dashboard at <code>admin.php</code>, bound to the
                loopback interface. Open it in your browser and you get <strong>403 Forbidden</strong> —
                your request isn't coming from <code>127.0.0.1</code>.</p>
                <p>Turn the URL fetcher into your proxy: have the server request the admin panel.
                Its request <em>does</em> come from loopback, so the dashboard renders — including the
                <code>admin_token</code> flag.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level2.php">
                <div class="form-group">
                    <label class="form-label" for="url_input">Target URL</label>
                    <input
                        type="text"
                        id="url_input"
                        name="url"
                        class="form-control"
                        placeholder="http://127.0.0.1/admin.php"
                        value="<?= htmlspecialchars($url) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Fetch URL</button>
                    <?php if ($url !== ''): ?>
                    <a href="level2.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <!-- Flag / result display -->
            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Flag Captured!</h3>
                <p><?= htmlspecialchars($flagMessage) ?></p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem; font-size:0.8rem;">
                    <a href="submit.php">Submit this flag &rarr;</a>
                </p>
            </div>
            <?php elseif ($url !== '' && $fetchError): ?>
            <div class="message error"><?= htmlspecialchars($fetchError) ?></div>
            <?php elseif ($url !== ''): ?>
            <div class="message info">Response received, but no admin token in it. Point the fetcher at the internal admin panel.</div>
            <?php endif; ?>

            <!-- ── Server-side fetch result ── -->
            <?php if ($url !== ''): ?>
            <div class="ssrf-output-section">
                <h4 style="margin:0.85rem 0 0.4rem; font-size:0.8rem; color:var(--text-muted);">Server-side response:</h4>
                <div class="output-box <?= $response === '' ? 'empty' : '' ?>"><?= $response === '' ? 'No response body.' : htmlspecialchars(substr($response, 0, 4000)) ?></div>
            </div>
            <?php endif; ?>

        </div><!-- /.challenge-panel -->
    </div><!-- /.challenge-layout -->

    <?= render_hint_section($hints) ?>
    <?= render_inline_flag_form($levelId, $_flag_result) ?>

    <div class="navigation">
        <a href="level<?= $prevLevel ?>.php" class="btn btn-secondary">&larr; Level <?= $prevLevel ?></a>
        <a href="submit.php" class="btn btn-secondary nav-center">Submit Flag</a>
        <a href="level<?= $nextLevel ?>.php" class="btn btn-secondary">Level <?= $nextLevel ?> &rarr;</a>
    </div>

</div><!-- /.container -->
</body>
</html>
