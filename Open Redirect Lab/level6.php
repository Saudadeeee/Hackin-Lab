<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 6;
$levelTitle = 'Userinfo (@) Host Spoof';
$prevLevel  = 5;
$nextLevel  = 7;

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
    <title>Level 6 — Userinfo (@) Host Spoof | Open Redirect Lab</title>
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
        <span class="level-badge">Level 6</span>
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
<span class="php-comment">// Extract the host: text between '://' and the next '/'</span>
preg_match(<span class="php-string">'#^https?://([^/]+)#i'</span>, <span class="php-variable">$next</span>, <span class="php-variable">$m</span>);
<span class="php-variable">$host</span> = <span class="php-variable">$m</span>[<span class="php-string">1</span>] ?? <span class="php-string">''</span>;
<span class="php-keyword">if</span> (str_starts_with(<span class="php-variable">$host</span>, <span class="php-string">'example-bank.local'</span>)) {
<span class="vuln-line">    header(<span class="php-string">"Location: "</span> . <span class="php-variable">$next</span>);   <span class="php-comment">// 'user@realhost' fools the check</span></span>
} <span class="php-keyword">else</span> {
    http_response_code(<span class="php-string">400</span>); <span class="php-keyword">echo</span> <span class="php-string">"blocked"</span>;
}<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The "host" is grabbed with a naive regex — everything between
                <code>://</code> and the next <code>/</code> — then prefix-checked. That span can contain
                <strong>userinfo</strong> before an <code>@</code>, which the browser treats as credentials, not the
                host. The real host lives <em>after</em> the <code>@</code>.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>This validator pulls the authority out of the URL with a regex and checks that it starts with the
                bank domain.</p>
                <p>Use the URL authority's <code>user@host</code> form so the check sees the trusted name first, while
                the browser connects to <code>evil.attacker.example</code>.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level6.php">
                <div class="form-group">
                    <label class="form-label" for="next_input">Redirect target (next parameter)</label>
                    <input
                        type="text"
                        id="next_input"
                        name="next"
                        class="form-control"
                        placeholder="e.g. https://example-bank.local@evil.attacker.example/"
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Test Redirect</button>
                    <?php if ($input !== ''): ?>
                    <a href="level6.php" class="btn btn-secondary">Clear</a>
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
                The extracted authority must start with the trusted name, but the browser's host must be the attacker's.
                What part of an authority comes before the real host?
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
