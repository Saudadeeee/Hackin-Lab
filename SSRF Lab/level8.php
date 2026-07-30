<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 8;
$levelTitle = 'Cloud Metadata Theft';
$prevLevel  = 7;
$nextLevel  = 9;

// ── Challenge logic ──────────────────────────────────────────
$url = $_GET['url'] ?? '';

$flag        = '';
$flagMessage = '';
$response    = '';
$blocked     = false;
$fetchError  = '';

if ($url !== '') {
    // Only real weak guard: require an http(s) scheme. The internal metadata
    // host itself is never blocked.
    $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
    if (!in_array($scheme, ['http', 'https'], true)) {
        $blocked = true;
    } else {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 4);
        $response = curl_exec($ch);
        if ($response === false) { $fetchError = curl_error($ch) ?: 'Request failed.'; $response = ''; }
        curl_close($ch);

        if (ssrf_captured($levelId, $response)) {
            $flag        = get_flag_for_level($levelId);
            $flagMessage = 'You reached the instance metadata service and leaked its IAM credentials.';
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
    <title>Level 8 — Cloud Metadata Theft | SSRF Lab</title>
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
        <span class="level-badge">Level 8</span>
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

<span class="php-comment">// Only checks the scheme — the metadata IP is wide open</span>
<span class="php-variable">$scheme</span> = parse_url(<span class="php-variable">$url</span>, PHP_URL_SCHEME);
<span class="php-keyword">if</span> (!in_array(<span class="php-variable">$scheme</span>, [<span class="php-string">'http'</span>, <span class="php-string">'https'</span>])) <span class="php-keyword">die</span>(<span class="php-string">'blocked'</span>);

<span class="php-variable">$ch</span> = curl_init(<span class="php-variable">$url</span>);
curl_setopt(<span class="php-variable">$ch</span>, CURLOPT_RETURNTRANSFER, <span class="php-keyword">true</span>);
<span class="vuln-line"><span class="php-variable">$response</span> = curl_exec(<span class="php-variable">$ch</span>); <span class="php-comment">// can reach 169.254.169.254</span></span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; No block on the link-local metadata address.
                On a real cloud host, <code>http://169.254.169.254/</code> serves instance
                credentials. This lab mocks that service (reachable only from inside the box), so the
                SSRF can enumerate the IAM role and steal its keys.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The app runs on a "cloud instance" whose metadata service answers at
                <code>169.254.169.254</code> — only reachable from the server itself.</p>
                <p>Walk the AWS-style path
                <code>/latest/meta-data/iam/security-credentials/&lt;role&gt;</code> (the role here is
                <code>ssrf-lab-role</code>) and leak the credentials document.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level8.php">
                <div class="form-group">
                    <label class="form-label" for="url_input">Metadata URL</label>
                    <input
                        type="text"
                        id="url_input"
                        name="url"
                        class="form-control"
                        placeholder="http://169.254.169.254/latest/meta-data/iam/security-credentials/ssrf-lab-role"
                        value="<?= htmlspecialchars($url) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Fetch URL</button>
                    <?php if ($url !== ''): ?>
                    <a href="level8.php" class="btn btn-secondary">Clear</a>
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
            <div class="message error">&#x1F6AB; Blocked — only <code>http</code>/<code>https</code> schemes are fetched.</div>
            <?php elseif ($url !== '' && $fetchError): ?>
            <div class="message error"><?= htmlspecialchars($fetchError) ?></div>
            <?php elseif ($url !== ''): ?>
            <div class="message info">Fetched, but no credentials in the response. Enumerate down to the role: <code>.../iam/security-credentials/ssrf-lab-role</code>.</div>
            <?php endif; ?>

            <!-- ── Server-side fetch result ── -->
            <?php if ($url !== '' && !$blocked): ?>
            <div class="ssrf-output-section">
                <h4 style="margin:0.85rem 0 0.4rem; font-size:0.8rem; color:var(--text-muted);">Metadata response:</h4>
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
