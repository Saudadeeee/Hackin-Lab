<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 5;
$levelTitle = 'Backslash Normalization';
$prevLevel  = 4;
$nextLevel  = 6;

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
    <title>Level 5 — Backslash Normalization | Open Redirect Lab</title>
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
<span class="php-variable">$next</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'next'</span>] ?? <span class="php-string">'/'</span>;
<span class="php-comment">// Block protocol-relative and absolute URLs</span>
<span class="php-keyword">if</span> (str_starts_with(<span class="php-variable">$next</span>, <span class="php-string">'//'</span>) || preg_match(<span class="php-string">'#^https?:#i'</span>, <span class="php-variable">$next</span>)) {
    http_response_code(<span class="php-string">400</span>); <span class="php-keyword">echo</span> <span class="php-string">"blocked"</span>; <span class="php-keyword">exit</span>;
}
<span class="php-keyword">if</span> (str_starts_with(<span class="php-variable">$next</span>, <span class="php-string">'/'</span>)) {
<span class="vuln-line">    header(<span class="php-string">"Location: "</span> . <span class="php-variable">$next</span>);   <span class="php-comment">// browser turns '\' into '/'</span></span>
}<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The filter blocks a literal <code>//</code> and any
                <code>http(s):</code> scheme, but browsers <strong>normalise backslashes to forward slashes</strong>
                while parsing a URL. A value that begins <code>/\</code> is not blocked, yet the browser reads it
                as <code>//</code> — protocol-relative.
            </div>
            <div class="lk-box"><h4><span class="lk-tag">PROOF</span>See the real header</h4>
                <div class="lk-body">
                    <p>The level page models the redirect instead of performing it, because a genuine 302 would
                    navigate you away before you could read the trace. <code>go.php</code> runs this same filter and,
                    when it accepts, really does call <code>header('Location: ...')</code>:</p>
                    <pre class="lk-sinkline">curl -i "http://localhost:8092/go.php?level=5&amp;next=&lt;your value&gt;"</pre>
                    <p class="text-muted">A rejected value returns 400 with no <code>Location</code> at all.</p>
                </div>
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>Now the endpoint explicitly rejects <code>//</code> and <code>http(s):</code> prefixes and only
                allows single-slash paths.</p>
                <p>Use a character the browser rewrites into a slash so that your value <em>becomes</em>
                protocol-relative after normalization, sending the browser to <code>evil.attacker.example</code>.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level5.php">
                <div class="form-group">
                    <label class="form-label" for="next_input">Redirect target (next parameter)</label>
                    <input
                        type="text"
                        id="next_input"
                        name="next"
                        class="form-control"
                        placeholder="e.g. /\evil.attacker.example"
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Test Redirect</button>
                    <?php if ($input !== ''): ?>
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
            <?php elseif ($vr['submitted']): ?>
            <div class="message error">
                Blocked or still on-site. Which slash-like character survives the <code>//</code> check but a browser
                rewrites into a slash?
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
