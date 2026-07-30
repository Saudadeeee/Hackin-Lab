<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 7;
$levelTitle = 'URL Parser Confusion';
$prevLevel  = 6;
$nextLevel  = 8;

// ── Challenge logic ──────────────────────────────────────────
$url = $_GET['url'] ?? '';

$flag        = '';
$flagMessage = '';
$response    = '';
$blocked     = false;
$authority   = '';
$fetchError  = '';

if ($url !== '') {
    // Flawed allowlist: grab the authority (up to the first '/') and just check
    // whether 'example.com' appears anywhere inside it. No real URL parsing.
    if (preg_match('#^https?://([^/]+)#i', $url, $m)) {
        $authority = $m[1];
    }
    if (stripos($authority, 'example.com') === false) {
        $blocked = true;
    } else {
        $ctx = stream_context_create(['http' => ['timeout' => 4, 'ignore_errors' => true]]);
        $response = @file_get_contents($url, false, $ctx);
        if ($response === false) {
            $response   = '';
            $fetchError = 'The request failed (host unreachable, timed out, or refused).';
        }
        if (ssrf_captured($levelId, $response)) {
            $flag        = get_flag_for_level($levelId);
            $flagMessage = 'The credentials before @ fooled the check; the real host was 127.0.0.1.';
        }
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
    <title>Level 7 — URL Parser Confusion | SSRF Lab</title>
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
        <span class="level-badge">Level 7</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-variable">$url</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'url'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// Grab the authority, then substring-match the allowed domain</span>
preg_match(<span class="php-string">'#^https?://([^/]+)#i'</span>, <span class="php-variable">$url</span>, <span class="php-variable">$m</span>);
<span class="php-variable">$authority</span> = <span class="php-variable">$m</span>[<span class="php-string">1</span>] ?? <span class="php-string">''</span>;
<span class="php-keyword">if</span> (stripos(<span class="php-variable">$authority</span>, <span class="php-string">'example.com'</span>) === <span class="php-keyword">false</span>) <span class="php-keyword">die</span>(<span class="php-string">'blocked'</span>);

<span class="vuln-line"><span class="php-variable">$response</span> = file_get_contents(<span class="php-variable">$url</span>);  <span class="php-comment">// connects to the REAL host</span></span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The authority of a URL can contain
                <em>userinfo</em> before an <code>@</code>. In
                <code>http://example.com@127.0.0.1/</code> the string <code>example.com</code> is just
                credentials — the real host is <code>127.0.0.1</code>. The naive substring check passes
                while the connection lands internally.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The allowlist insists the URL points at <code>example.com</code> — but it "parses"
                the host with a substring check instead of a real URL parser.</p>
                <p>Craft a URL whose authority <em>contains</em> <code>example.com</code> yet actually
                connects to <code>127.0.0.1</code>, then read <code>internal.php?level=7</code>.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level7.php">
                <div class="form-group">
                    <label class="form-label" for="url_input">Target URL (must "contain" example.com)</label>
                    <input
                        type="text"
                        id="url_input"
                        name="url"
                        class="form-control"
                        placeholder="http://example.com@127.0.0.1/internal.php?level=7"
                        value="<?= htmlspecialchars($url) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Fetch URL</button>
                    <?php if ($url !== ''): ?>
                    <a href="level7.php" class="btn btn-secondary">Clear</a>
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
            <?php elseif ($blocked): ?>
            <div class="message error">&#x1F6AB; Blocked — the authority
                <code><?= htmlspecialchars($authority ?: '(none)') ?></code> does not contain
                <code>example.com</code>.</div>
            <?php elseif ($url !== '' && $fetchError): ?>
            <div class="message error"><?= htmlspecialchars($fetchError) ?></div>
            <?php elseif ($url !== ''): ?>
            <div class="message info">Passed the check, but no internal flag returned. Make sure the real host resolves to loopback and the path is <code>internal.php?level=7</code>.</div>
            <?php endif; ?>

            <!-- ── Server-side fetch result ── -->
            <?php if ($url !== '' && !$blocked): ?>
            <div class="ssrf-output-section">
                <h4 style="margin:0.85rem 0 0.4rem; font-size:0.8rem; color:var(--text-muted);">
                    Allowlist saw authority: <code><?= htmlspecialchars($authority) ?></code>
                </h4>
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
