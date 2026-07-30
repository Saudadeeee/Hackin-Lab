<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 3;
$levelTitle = 'Blind SSRF';
$prevLevel  = 2;
$nextLevel  = 4;

// ── Challenge logic ──────────────────────────────────────────
$url = $_GET['url'] ?? '';

$flag        = '';
$flagMessage = '';
$dispatched  = false;
$confirmed   = false;
$beaconLine  = '';

if ($url !== '') {
    $dispatched = true;
    // The server fetches the URL, but the response body is NEVER shown to you.
    $ctx = stream_context_create(['http' => ['timeout' => 4, 'ignore_errors' => true]]);
    $response = @file_get_contents($url, false, $ctx);
    $response = ($response === false) ? '' : $response;

    // The confirmation happens entirely server-side: we inspect the response
    // the server received (which you never see) for proof the beacon was hit.
    if (ssrf_captured($levelId, $response)) {
        $flag        = get_flag_for_level($levelId);
        $flagMessage = 'The internal beacon was reached — confirmed on the server, not shown to you.';
        $confirmed   = true;
    }
}

// Read the last recorded beacon hit (server-side proof of the blind request).
$logFile = __DIR__ . '/beacon_hits.log';
if (is_file($logFile)) {
    $lines = array_values(array_filter(explode("\n", (string)@file_get_contents($logFile))));
    if (!empty($lines)) $beaconLine = end($lines);
}

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 3 — Blind SSRF | SSRF Lab</title>
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
        <span class="level-badge">Level 3</span>
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

<span class="php-variable">$ctx</span> = stream_context_create([<span class="php-string">'http'</span> =&gt; [<span class="php-string">'timeout'</span> =&gt; <span class="php-string">4</span>]]);
<span class="vuln-line"><span class="php-variable">$response</span> = file_get_contents(<span class="php-variable">$url</span>, <span class="php-keyword">false</span>, <span class="php-variable">$ctx</span>);</span>

<span class="php-comment">// BLIND: the body is never echoed back to the user.</span>
<span class="php-comment">// The server checks it privately and only reports success.</span>
<span class="php-keyword">if</span> (ssrf_captured(<span class="php-string">3</span>, <span class="php-variable">$response</span>)) {
    <span class="php-variable">$confirmed</span> = <span class="php-keyword">true</span>;   <span class="php-comment">// you only ever see this bit</span>
}</code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The request still fires against any URL you
                choose, but the response body is withheld. This is <strong>blind SSRF</strong>: you
                can't read the reply, yet the internal service (<code>beacon.php</code>) is reached
                and the server confirms it happened.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>This "link health checker" fetches your URL but only tells you whether the request
                went through — it never shows the response. Internally there is a loopback-only
                <code>beacon.php</code> that logs every hit.</p>
                <p>Fire the server's request at the internal beacon. You won't see its reply, but the
                server will confirm — from its own side — that the internal service was reached.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level3.php">
                <div class="form-group">
                    <label class="form-label" for="url_input">Target URL</label>
                    <input
                        type="text"
                        id="url_input"
                        name="url"
                        class="form-control"
                        placeholder="http://127.0.0.1/beacon.php"
                        value="<?= htmlspecialchars($url) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Check Link</button>
                    <?php if ($url !== ''): ?>
                    <a href="level3.php" class="btn btn-secondary">Clear</a>
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
            <?php elseif ($dispatched): ?>
            <div class="message info">Request dispatched. The response is hidden (blind), and it did
                not prove the internal beacon was reached. Try targeting <code>beacon.php</code> on loopback.</div>
            <?php endif; ?>

            <!-- ── Blind status (no body ever shown) ── -->
            <?php if ($dispatched): ?>
            <div class="ssrf-output-section">
                <h4 style="margin:0.85rem 0 0.4rem; font-size:0.8rem; color:var(--text-muted);">Request status:</h4>
                <div class="output-box">
Request dispatched by server &#x2713;
Response body: <em>withheld (blind SSRF)</em>
<?php if ($confirmed): ?>Server-side confirmation: internal beacon HIT.
<?php else: ?>Server-side confirmation: internal beacon NOT hit.
<?php endif; ?><?php if ($beaconLine !== ''): ?>
Latest beacon log entry: <?= htmlspecialchars($beaconLine) ?>
<?php endif; ?>
                </div>
                <p style="font-size:0.75rem; color:var(--text-faint); margin-top:0.4rem;">
                    You never see the beacon's reply — only the server does. That is the essence of blind SSRF.
                </p>
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
