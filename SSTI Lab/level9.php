<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 9;
$levelTitle = 'Nested Delimiter Bypass';
$prevLevel  = 8;
$nextLevel  = 10;

$input = $_GET['tpl'] ?? '';

$run  = ['blocked' => false, 'reason' => '', 'rendered' => '', 'executed' => false];
$flag = '';
$flagMessage = '';

if ($input !== '') {
    $run = run_ssti_level($levelId, $input);
    if (ssti_flag_earned($levelId, $input, $run)) {
        $flag        = get_flag_for_level($levelId);
        $flagMessage = 'A template tag survived the single-pass stripper and executed.';
    }
}

// For display: show the value that actually reaches the engine after stripping.
$strippedForDisplay = ($input !== '') ? ssti_strip_outer_delims($input) : '';

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 9 — Nested Delimiter Bypass | SSTI Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x26A1;</span> SSTI Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">

    <div class="level-header">
        <span class="level-badge">Level 9</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-variable">$tpl</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'tpl'</span>];

<span class="php-comment">// "Defence": strip out the template delimiters before rendering.</span>
<span class="php-comment">// Removes only the FIRST '{{' and the LAST '}}' — one pass, not recursive.</span>
<span class="vuln-line"><span class="php-variable">$p</span> = <span class="php-function">strpos</span>(<span class="php-variable">$tpl</span>, <span class="php-string">'{{'</span>);  <span class="php-keyword">if</span> (<span class="php-variable">$p</span> !== <span class="php-keyword">false</span>) <span class="php-variable">$tpl</span> = <span class="php-function">substr_replace</span>(<span class="php-variable">$tpl</span>, <span class="php-string">''</span>, <span class="php-variable">$p</span>, 2);</span>
<span class="vuln-line"><span class="php-variable">$q</span> = <span class="php-function">strrpos</span>(<span class="php-variable">$tpl</span>, <span class="php-string">'}}'</span>); <span class="php-keyword">if</span> (<span class="php-variable">$q</span> !== <span class="php-keyword">false</span>) <span class="php-variable">$tpl</span> = <span class="php-function">substr_replace</span>(<span class="php-variable">$tpl</span>, <span class="php-string">''</span>, <span class="php-variable">$q</span>, 2);</span>

<span class="php-variable">$out</span> = <span class="php-function">render_template</span>(<span class="php-variable">$tpl</span>); <span class="php-comment">// same eval() engine as before</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The stripper unwraps exactly one delimiter pair and is
                never re-applied. Nesting <code>{{{{ ... }}}}</code> means removing the outer braces leaves a
                perfectly valid <code>{{ ... }}</code> tag for the engine.
            </div>
        </div>

        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The developer decided the safest fix is to "just delete the template tags" before
                rendering. Their stripper removes one <code>{{ ... }}</code> layer — but only once.</p>
                <p>Send a payload that <strong>survives</strong> the single strip pass and still executes.</p>
            </div>

            <form method="get" action="level9.php">
                <div class="form-group">
                    <label class="form-label" for="tpl_input">Template (tpl parameter)</label>
                    <input
                        type="text"
                        id="tpl_input"
                        name="tpl"
                        class="form-control"
                        placeholder="e.g. {{{{7*7}}}}"
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Render Template</button>
                    <?php if ($input !== ''): ?>
                    <a href="level9.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Flag Captured!</h3>
                <p><?= htmlspecialchars($flagMessage) ?></p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem; font-size:0.8rem;">
                    <a href="submit.php">Submit this flag &rarr;</a>
                </p>
            </div>
            <?php elseif ($input !== ''): ?>
            <div class="message error">No tag survived the stripper. Nest the braces — try <code>{{{{7*7}}}}</code>.</div>
            <?php endif; ?>

            <?php if ($input !== ''): ?>
            <div class="xss-output-section">
                <h4>After stripper (what the engine receives):</h4>
                <div class="output-box"><?= htmlspecialchars($strippedForDisplay) !== '' ? htmlspecialchars($strippedForDisplay) : '(empty)' ?></div>
                <h4 style="margin-top:0.75rem;">Live Output (server-rendered template):</h4>
                <div class="output-box"><?= trim($run['rendered']) !== '' ? htmlspecialchars($run['rendered']) : '(empty result)' ?></div>
                <p class="xss-sandbox-note">
                    The top box is the input after one strip pass; the bottom box is what the engine executed.
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
