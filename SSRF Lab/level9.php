<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 9;
$levelTitle = 'Hostname Allowlist Bypass';
$prevLevel  = 8;
$nextLevel  = 10;

// ── Challenge logic ──────────────────────────────────────────
$url = $_GET['url'] ?? '';

$flag        = '';
$flagMessage = '';
$response    = '';
$blocked     = false;
$host        = '';
$fetchError  = '';

if ($url !== '') {
    // Allowlist by SUBSTRING: trusts any hostname that contains 'corp-internal'.
    $host = strtolower((string)parse_url($url, PHP_URL_HOST));
    if (strpos($host, 'corp-internal') === false) {
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
            $flagMessage = 'An attacker-named host containing the magic substring resolved to loopback.';
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
    <title>Level 9 — Hostname Allowlist Bypass | SSRF Lab</title>
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
        <span class="level-badge">Level 9</span>
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

<span class="php-comment">// "Allowlist" by hostname substring — trusts anything</span>
<span class="php-comment">// whose host contains our internal naming convention</span>
<span class="php-variable">$host</span> = parse_url(<span class="php-variable">$url</span>, PHP_URL_HOST);
<span class="php-keyword">if</span> (strpos(<span class="php-variable">$host</span>, <span class="php-string">'corp-internal'</span>) === <span class="php-keyword">false</span>) <span class="php-keyword">die</span>(<span class="php-string">'blocked'</span>);

<span class="vuln-line"><span class="php-variable">$response</span> = file_get_contents(<span class="php-variable">$url</span>);  <span class="php-comment">// resolves attacker DNS</span></span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; Trust is decided by a substring of the hostname.
                You control your own DNS names, so any host you register that <em>contains</em>
                <code>corp-internal</code> — and points at <code>127.0.0.1</code> — satisfies the check
                and still reaches the internal service.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The allowlist assumes only its own servers are named with <code>corp-internal</code>
                in them, and trusts any hostname containing that substring.</p>
                <p>The lab provides an attacker-controlled name that both contains the magic substring
                and resolves to loopback: <code>corp-internal.attacker.local</code>. Use it to reach
                <code>internal.php?level=9</code>.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level9.php">
                <div class="form-group">
                    <label class="form-label" for="url_input">Target URL (host must contain corp-internal)</label>
                    <input
                        type="text"
                        id="url_input"
                        name="url"
                        class="form-control"
                        placeholder="http://corp-internal.attacker.local/internal.php?level=9"
                        value="<?= htmlspecialchars($url) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Fetch URL</button>
                    <?php if ($url !== ''): ?>
                    <a href="level9.php" class="btn btn-secondary">Clear</a>
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
            <div class="message error">&#x1F6AB; Host <code><?= htmlspecialchars($host ?: '(none)') ?></code>
                does not contain the trusted substring <code>corp-internal</code>.</div>
            <?php elseif ($url !== '' && $fetchError): ?>
            <div class="message error"><?= htmlspecialchars($fetchError) ?></div>
            <?php elseif ($url !== ''): ?>
            <div class="message info">Passed the substring check, but no internal flag returned. Use a host that contains <code>corp-internal</code> and maps to loopback.</div>
            <?php endif; ?>

            <!-- ── Server-side fetch result ── -->
            <?php if ($url !== '' && !$blocked): ?>
            <div class="ssrf-output-section">
                <h4 style="margin:0.85rem 0 0.4rem; font-size:0.8rem; color:var(--text-muted);">
                    Allowlist accepted host: <code><?= htmlspecialchars($host) ?></code>
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
