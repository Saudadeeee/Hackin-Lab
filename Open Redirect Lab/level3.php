<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 3;
$levelTitle = 'Prefix Allowlist Bypass';
$prevLevel  = 2;
$nextLevel  = 4;

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
    <title>Level 3 — Prefix Allowlist Bypass | Open Redirect Lab</title>
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
<span class="php-variable">$next</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'next'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$host</span> = parse_url(<span class="php-variable">$next</span>, PHP_URL_HOST) ?? <span class="php-string">''</span>;
<span class="php-comment">// "Only redirect to our bank domain"</span>
<span class="php-keyword">if</span> (str_starts_with(<span class="php-variable">$host</span>, <span class="php-string">'example-bank.local'</span>)) {
<span class="vuln-line">    header(<span class="php-string">"Location: "</span> . <span class="php-variable">$next</span>);   <span class="php-comment">// prefix match on the host</span></span>
} <span class="php-keyword">else</span> {
    http_response_code(<span class="php-string">400</span>); <span class="php-keyword">echo</span> <span class="php-string">"blocked"</span>;
}<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The host is parsed correctly, but the allowlist uses a
                <strong>prefix</strong> check instead of equality. Any hostname that merely <em>begins</em> with
                <code>example-bank.local</code> passes — including a subdomain label on a domain you control.
            </div>
            <div class="lk-box"><h4><span class="lk-tag">PROOF</span>See the real header</h4>
                <div class="lk-body">
                    <p>The level page models the redirect instead of performing it, because a genuine 302 would
                    navigate you away before you could read the trace. <code>go.php</code> runs this same filter and,
                    when it accepts, really does call <code>header('Location: ...')</code>:</p>
                    <pre class="lk-sinkline">curl -i "http://localhost:8092/go.php?level=3&amp;next=&lt;your value&gt;"</pre>
                    <p class="text-muted">A rejected value returns 400 with no <code>Location</code> at all.</p>
                </div>
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>This time the code parses the URL host and requires it to start with the trusted bank domain.</p>
                <p>Craft a URL whose <code>parse_url()</code> host starts with <code>example-bank.local</code> but whose
                real registrable domain is <code>evil.attacker.example</code>.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level3.php">
                <div class="form-group">
                    <label class="form-label" for="next_input">Redirect target (next parameter)</label>
                    <input
                        type="text"
                        id="next_input"
                        name="next"
                        class="form-control"
                        placeholder="e.g. https://example-bank.local.evil.attacker.example/"
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Test Redirect</button>
                    <?php if ($input !== ''): ?>
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
            <?php elseif ($vr['submitted']): ?>
            <div class="message error">
                The host must <em>start with</em> the trusted name to pass, yet resolve to the attacker domain.
                Think about where a subdomain label sits in a hostname.
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
