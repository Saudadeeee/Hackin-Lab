<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 8;
$levelTitle = 'Dangerous Scheme Redirect';
$prevLevel  = 7;
$nextLevel  = 9;

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
    <title>Level 8 — Dangerous Scheme Redirect | Open Redirect Lab</title>
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
<span class="php-variable">$next</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'next'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$host</span> = parse_url(<span class="php-variable">$next</span>, PHP_URL_HOST);
<span class="php-comment">// "No foreign host? Then it's safe."</span>
<span class="php-keyword">if</span> (<span class="php-variable">$host</span> === <span class="php-keyword">null</span> || <span class="php-variable">$host</span> === <span class="php-string">'example-bank.local'</span>) {
<span class="vuln-line">    <span class="php-keyword">echo</span> <span class="php-string">"&lt;a href='"</span> . <span class="php-variable">$next</span> . <span class="php-string">"'&gt;Continue &rarr;&lt;/a&gt;"</span>;</span>
} <span class="php-keyword">else</span> {
    http_response_code(<span class="php-string">400</span>); <span class="php-keyword">echo</span> <span class="php-string">"blocked"</span>;
}<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The allowlist only asks "is there a foreign <em>host</em>?".
                Schemes like <code>javascript:</code> and <code>data:</code> have <strong>no host</strong>, so
                <code>parse_url()</code> returns <code>null</code> and they pass. Dropped into an <code>href</code>,
                the browser executes them — an open redirect that becomes script execution.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>This "safe redirect" only blocks values that resolve to a foreign host. It never considers the
                URL <em>scheme</em>.</p>
                <p>Submit a value whose <code>parse_url()</code> host is <code>null</code> but which the browser would
                execute rather than navigate. The lab flags any dangerous scheme that survives the check.</p>
            </div>

            <!-- Payload input form -->
            <form method="get" action="level8.php">
                <div class="form-group">
                    <label class="form-label" for="next_input">Redirect target (next parameter)</label>
                    <input
                        type="text"
                        id="next_input"
                        name="next"
                        class="form-control"
                        placeholder="e.g. javascript:alert(document.domain)"
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Test Redirect</button>
                    <?php if ($input !== ''): ?>
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
            <?php elseif ($vr['submitted']): ?>
            <div class="message error">
                A same-site path is accepted but harmless; an absolute foreign URL is blocked. Which schemes carry no
                host yet still run in the browser?
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
