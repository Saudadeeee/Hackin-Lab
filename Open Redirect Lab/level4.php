<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 4;
$levelTitle = 'Substring Allowlist Bypass';
$prevLevel  = 3;
$nextLevel  = 5;

// ── Challenge logic ──────────────────────────────────────────
$input = $_GET['next'] ?? '';

$vr          = verify_redirect($levelId, $input);
$flag        = $vr['captured'] ? get_flag_for_level($levelId) : '';
$flagMessage = $vr['message'];

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 4 — Substring Allowlist Bypass | Open Redirect Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x21AA;</span> Open Redirect Lab</div>
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
<span class="php-variable">$next</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'next'</span>] ?? <span class="php-string">''</span>;
<span class="php-comment">// "The bank domain must appear in the URL"</span>
<span class="php-keyword">if</span> (str_contains(<span class="php-variable">$next</span>, <span class="php-string">'example-bank.local'</span>)) {
<span class="vuln-line">    header(<span class="php-string">"Location: "</span> . <span class="php-variable">$next</span>);   <span class="php-comment">// substring anywhere passes</span></span>
} <span class="php-keyword">else</span> {
    http_response_code(<span class="php-string">400</span>); <span class="php-keyword">echo</span> <span class="php-string">"blocked"</span>;
}<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The allowlist only requires that the trusted name appear
                <em>somewhere</em> in the string. It can live in the path, query, or fragment while the real host
                stays attacker-controlled.
            </div>
            <div class="lk-box"><h4><span class="lk-tag">PROOF</span>See the real header</h4>
                <div class="lk-body">
                    <p>The level page models the redirect instead of performing it, because a genuine 302 would
                    navigate you away before you could read the trace. <code>go.php</code> runs this same filter and,
                    when it accepts, really does call <code>header('Location: ...')</code>:</p>
                    <pre class="lk-sinkline">curl -i "http://localhost:8092/go.php?level=4&amp;next=&lt;your value&gt;"</pre>
                    <p class="text-muted">A rejected value returns 400 with no <code>Location</code> at all.</p>
                </div>
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The developer "fixed" the previous bug by requiring the string <code>example-bank.local</code> to be
                present anywhere in <code>next</code>.</p>
                <p>Build a URL that contains that substring but whose browser-resolved host is
                <code>evil.attacker.example</code>.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level4.php">
                <div class="form-group">
                    <label class="form-label" for="next_input">Redirect target (next parameter)</label>
                    <input
                        type="text"
                        id="next_input"
                        name="next"
                        class="form-control"
                        placeholder="e.g. https://evil.attacker.example/example-bank.local"
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Test Redirect</button>
                    <?php if ($input !== ''): ?>
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
            <?php elseif ($vr['submitted']): ?>
            <div class="message error">
                The trusted substring must be present, but the browser's host must be the attacker's. Where can you
                hide the substring so it is not the host?
            </div>
            <?php endif; ?>

            <?= render_redirect_result($vr) ?>

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
