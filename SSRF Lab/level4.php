<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 4;
$levelTitle = 'Host Blocklist Bypass';
$prevLevel  = 3;
$nextLevel  = 5;

// ── Challenge logic ──────────────────────────────────────────
$url = $_GET['url'] ?? '';

$flag        = '';
$flagMessage = '';
$response    = '';
$blocked     = false;
$fetchError  = '';

if ($url !== '') {
    // Naive blocklist: reject the two exact spellings of loopback.
    if (stripos($url, 'localhost') !== false || stripos($url, '127.0.0.1') !== false) {
        $blocked = true;
    } else {
        // curl resolves 127.1, 0, decimal and [::1] all to the local host.
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 4);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        $response = curl_exec($ch);
        if ($response === false) { $fetchError = curl_error($ch) ?: 'Request failed.'; $response = ''; }
        curl_close($ch);

        if (ssrf_captured($levelId, $response)) {
            $flag        = get_flag_for_level($levelId);
            $flagMessage = 'An alternate loopback encoding slipped past the blocklist.';
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
    <title>Level 4 — Host Blocklist Bypass | SSRF Lab</title>
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
        <span class="level-badge">Level 4</span>
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

<span class="php-comment">// Blocklist: reject the obvious loopback spellings</span>
<span class="php-keyword">if</span> (stripos(<span class="php-variable">$url</span>, <span class="php-string">'localhost'</span>) !== <span class="php-keyword">false</span> ||
    stripos(<span class="php-variable">$url</span>, <span class="php-string">'127.0.0.1'</span>) !== <span class="php-keyword">false</span>) {
    <span class="php-keyword">die</span>(<span class="php-string">'blocked'</span>);
}
<span class="php-variable">$ch</span> = curl_init(<span class="php-variable">$url</span>);
curl_setopt(<span class="php-variable">$ch</span>, CURLOPT_RETURNTRANSFER, <span class="php-keyword">true</span>);
<span class="vuln-line"><span class="php-variable">$response</span> = curl_exec(<span class="php-variable">$ch</span>);   <span class="php-comment">// curl expands 127.1, 0, decimal, [::1]</span></span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The filter is a plain string match on
                <code>127.0.0.1</code> and <code>localhost</code>. IPv4 has many equivalent forms —
                <code>127.1</code>, the integer <code>0</code>, the decimal <code>2130706433</code>,
                and IPv6 <code>[::1]</code> — that curl happily resolves to loopback but the blocklist
                never recognises.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The developer "fixed" SSRF by blocking the strings <code>localhost</code> and
                <code>127.0.0.1</code>. Everything else is fetched by curl.</p>
                <p>Reach <code>internal.php?level=4</code> on loopback using an address encoding that
                doesn't contain either blocked string.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level4.php">
                <div class="form-group">
                    <label class="form-label" for="url_input">Target URL</label>
                    <input
                        type="text"
                        id="url_input"
                        name="url"
                        class="form-control"
                        placeholder="http://2130706433/internal.php?level=4"
                        value="<?= htmlspecialchars($url) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Fetch URL</button>
                    <?php if ($url !== ''): ?>
                    <a href="level4.php" class="btn btn-secondary">Clear</a>
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
            <div class="message error">&#x1F6AB; Blocked by the host filter — your URL contains
                <code>localhost</code> or <code>127.0.0.1</code>. Encode loopback differently.</div>
            <?php elseif ($url !== '' && $fetchError): ?>
            <div class="message error"><?= htmlspecialchars($fetchError) ?></div>
            <?php elseif ($url !== ''): ?>
            <div class="message info">Fetched, but no internal flag in the response. Aim the alternate encoding at <code>internal.php?level=4</code>.</div>
            <?php endif; ?>

            <!-- ── Server-side fetch result ── -->
            <?php if ($url !== '' && !$blocked): ?>
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
