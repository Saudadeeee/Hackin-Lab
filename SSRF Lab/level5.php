<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 5;
$levelTitle = 'Redirect-Based SSRF';
$prevLevel  = 4;
$nextLevel  = 6;

// ── Challenge logic ──────────────────────────────────────────
$url = $_GET['url'] ?? '';

$flag        = '';
$flagMessage = '';
$response    = '';
$blocked     = false;
$checkedHost = '';
$fetchError  = '';

$allowedHosts = ['feed.local'];

if ($url !== '') {
    // Allowlist validates ONLY the host of the submitted URL...
    $checkedHost = strtolower((string)parse_url($url, PHP_URL_HOST));
    if (!in_array($checkedHost, $allowedHosts, true)) {
        $blocked = true;
    } else {
        // ...but the fetcher blindly FOLLOWS redirects to wherever they point.
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 4);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);  // <-- the flaw
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        $response = curl_exec($ch);
        if ($response === false) { $fetchError = curl_error($ch) ?: 'Request failed.'; $response = ''; }
        curl_close($ch);

        if (ssrf_captured($levelId, $response)) {
            $flag        = get_flag_for_level($levelId);
            $flagMessage = 'The allowlist trusted the first hop; curl followed the 302 into loopback.';
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
    <title>Level 5 — Redirect-Based SSRF | SSRF Lab</title>
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
        <span class="level-badge">Level 5</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-variable">$url</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'url'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$allowed</span> = [<span class="php-string">'feed.local'</span>];

<span class="php-comment">// Only the FIRST host is validated against the allowlist</span>
<span class="php-variable">$host</span> = parse_url(<span class="php-variable">$url</span>, PHP_URL_HOST);
<span class="php-keyword">if</span> (!in_array(<span class="php-variable">$host</span>, <span class="php-variable">$allowed</span>)) <span class="php-keyword">die</span>(<span class="php-string">'blocked'</span>);

<span class="php-variable">$ch</span> = curl_init(<span class="php-variable">$url</span>);
curl_setopt(<span class="php-variable">$ch</span>, CURLOPT_RETURNTRANSFER, <span class="php-keyword">true</span>);
<span class="vuln-line">curl_setopt(<span class="php-variable">$ch</span>, CURLOPT_FOLLOWLOCATION, <span class="php-keyword">true</span>); <span class="php-comment">// follows 302 anywhere</span></span>
<span class="php-variable">$response</span> = curl_exec(<span class="php-variable">$ch</span>);</code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The allowlist checks only the host of the URL you
                submit. Because <code>CURLOPT_FOLLOWLOCATION</code> is on, a page on the trusted host
                can <code>302</code>-redirect the fetcher to an internal address — and curl follows it,
                no second check performed.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>Only the trusted feed host <code>feed.local</code> is allowed. But that host serves
                an open redirector, <code>redirector.php?url=...</code>, which bounces to any target.</p>
                <p>Submit a <code>feed.local</code> URL that passes the allowlist and redirects the
                fetcher onward to <code>internal.php?level=5</code> on loopback.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level5.php">
                <div class="form-group">
                    <label class="form-label" for="url_input">Target URL (host must be feed.local)</label>
                    <input
                        type="text"
                        id="url_input"
                        name="url"
                        class="form-control"
                        placeholder="http://feed.local/redirector.php?url=http://127.0.0.1/internal.php?level=5"
                        value="<?= htmlspecialchars($url) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Fetch URL</button>
                    <?php if ($url !== ''): ?>
                    <a href="level5.php" class="btn btn-secondary">Clear</a>
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
            <div class="message error">&#x1F6AB; Host <code><?= htmlspecialchars($checkedHost ?: '(none)') ?></code>
                is not on the allowlist. Only <code>feed.local</code> is permitted — use its redirector.</div>
            <?php elseif ($url !== '' && $fetchError): ?>
            <div class="message error"><?= htmlspecialchars($fetchError) ?></div>
            <?php elseif ($url !== ''): ?>
            <div class="message info">Allowed host fetched, but no internal flag came back. Make the redirector point at <code>internal.php?level=5</code>.</div>
            <?php endif; ?>

            <!-- ── Server-side fetch result ── -->
            <?php if ($url !== '' && !$blocked): ?>
            <div class="ssrf-output-section">
                <h4 style="margin:0.85rem 0 0.4rem; font-size:0.8rem; color:var(--text-muted);">Server-side response (after redirects):</h4>
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
