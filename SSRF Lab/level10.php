<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 10;
$levelTitle = 'Multi-Layer WAF Bypass';
$prevLevel  = 9;
$nextLevel  = 0; // last level

// ── Challenge logic ──────────────────────────────────────────
$url = $_GET['url'] ?? '';

$flag        = '';
$flagMessage = '';
$response    = '';
$blocked     = false;
$blockReason = '';
$fetchError  = '';

if ($url !== '') {
    $low = strtolower($url);

    // Layer 1 — scheme must be http/https (kills file://, gopher://, dict://)
    $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
    if (!in_array($scheme, ['http', 'https'], true)) {
        $blocked = true; $blockReason = 'scheme must be http/https';
    }
    // Layer 2 — reject known loopback / link-local spellings
    elseif (
        strpos($low, '127.0.0.1') !== false ||
        strpos($low, 'localhost') !== false ||
        strpos($low, '::1')       !== false ||
        strpos($low, '169.254')   !== false
    ) {
        $blocked = true; $blockReason = 'blocked host literal';
    }
    // Layer 3 — keyword filter
    elseif (strpos($low, 'metadata') !== false || strpos($low, '@') !== false) {
        $blocked = true; $blockReason = 'blocked keyword (metadata / @)';
    }
    else {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 4);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        $response = curl_exec($ch);
        if ($response === false) { $fetchError = curl_error($ch) ?: 'Request failed.'; $response = ''; }
        curl_close($ch);

        if (ssrf_captured($levelId, $response)) {
            $flag        = get_flag_for_level($levelId);
            $flagMessage = 'One vector — decimal-encoded loopback — survived all three filter layers.';
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
    <title>Level 10 — Multi-Layer WAF Bypass | SSRF Lab</title>
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
        <span class="level-badge">Level 10</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-expert">Expert</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-variable">$url</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'url'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$low</span> = strtolower(<span class="php-variable">$url</span>);

<span class="php-comment">// Layer 1: scheme must be http/https</span>
<span class="php-keyword">if</span> (!in_array(parse_url(<span class="php-variable">$url</span>, PHP_URL_SCHEME), [<span class="php-string">'http'</span>,<span class="php-string">'https'</span>])) <span class="php-keyword">die</span>();
<span class="php-comment">// Layer 2: block loopback / link-local literals</span>
<span class="vuln-line"><span class="php-keyword">foreach</span> ([<span class="php-string">'127.0.0.1'</span>,<span class="php-string">'localhost'</span>,<span class="php-string">'::1'</span>,<span class="php-string">'169.254'</span>] <span class="php-keyword">as</span> <span class="php-variable">$b</span>)
    <span class="php-keyword">if</span> (strpos(<span class="php-variable">$low</span>, <span class="php-variable">$b</span>) !== <span class="php-keyword">false</span>) <span class="php-keyword">die</span>();</span>
<span class="php-comment">// Layer 3: keyword filter</span>
<span class="php-keyword">if</span> (strpos(<span class="php-variable">$low</span>,<span class="php-string">'metadata'</span>)!==<span class="php-keyword">false</span> || strpos(<span class="php-variable">$low</span>,<span class="php-string">'@'</span>)!==<span class="php-keyword">false</span>) <span class="php-keyword">die</span>();

<span class="php-variable">$response</span> = curl_exec(curl_init(<span class="php-variable">$url</span>)); <span class="php-comment">// only survivors reach here</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; Three layers stack the earlier defences — no
                <code>file://</code> (L6), no loopback literals (L4), no <code>@</code> userinfo (L7),
                no metadata host (L8). But Layer 2 only blocks specific <em>spellings</em>. The 32-bit
                decimal form of <code>127.0.0.1</code> — <code>2130706433</code> — matches none of the
                strings and still connects to loopback.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The "WAF" applies three filters in sequence: an <code>http(s)</code>-only scheme
                check, a block on loopback/link-local literals, and a keyword filter on
                <code>metadata</code> and <code>@</code>.</p>
                <p>Every trick from the earlier levels is individually blocked. Find the one loopback
                encoding that trips <em>none</em> of the layers and reach
                <code>internal.php?level=10</code>.</p>
            </div>

            <!-- Filter summary -->
            <div style="background:var(--bg); border:1px solid var(--border); border-radius:var(--radius);
                        padding:0.75rem 1rem; font-size:0.82rem;">
                <div style="font-weight:700; color:var(--text-muted); text-transform:uppercase;
                            letter-spacing:0.06em; font-size:0.76rem; margin-bottom:0.5rem;">Filter Coverage</div>
                <div style="display:flex; flex-direction:column; gap:0.3rem;">
                    <div><span style="color:#b5766e;">Layer 1:</span> scheme must be <code>http</code> / <code>https</code></div>
                    <div><span style="color:#b5766e;">Layer 2:</span> <code>127.0.0.1</code> <code>localhost</code> <code>::1</code> <code>169.254</code></div>
                    <div><span style="color:#b5766e;">Layer 3:</span> <code>metadata</code> <code>@</code></div>
                    <div style="margin-top:0.35rem; color:#7fa06d;"><strong>Not covered:</strong> decimal / octal IP encodings of loopback</div>
                </div>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level10.php">
                <div class="form-group">
                    <label class="form-label" for="url_input">Target URL</label>
                    <input
                        type="text"
                        id="url_input"
                        name="url"
                        class="form-control"
                        placeholder="http://2130706433/internal.php?level=10"
                        value="<?= htmlspecialchars($url) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Fetch URL</button>
                    <?php if ($url !== ''): ?>
                    <a href="level10.php" class="btn btn-secondary">Clear</a>
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
            <div class="message error">&#x1F6AB; Blocked by the WAF — <?= htmlspecialchars($blockReason) ?>.
                Combine what survives all three layers.</div>
            <?php elseif ($url !== '' && $fetchError): ?>
            <div class="message error"><?= htmlspecialchars($fetchError) ?></div>
            <?php elseif ($url !== ''): ?>
            <div class="message info">Passed the WAF, but no internal flag returned. Point the surviving vector at <code>internal.php?level=10</code>.</div>
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
        <a href="submit.php" class="btn btn-success">&#x1F3C6; Submit Flags &rarr;</a>
    </div>

</div><!-- /.container -->
</body>
</html>
