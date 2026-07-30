<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 10;
$levelTitle = 'Multi-Layer WAF Bypass';
$prevLevel  = 9;

$input = $_GET['tpl'] ?? '';

$run  = ['blocked' => false, 'reason' => '', 'rendered' => '', 'executed' => false];
$flag = '';
$flagMessage = '';

if ($input !== '') {
    $run = run_ssti_level($levelId, $input);
    if (ssti_flag_earned($levelId, $input, $run)) {
        $flag        = get_flag_for_level($levelId);
        $flagMessage = 'One vector beat all three WAF layers and executed a command. Mastery.';
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
    <title>Level 10 — Multi-Layer WAF Bypass | SSTI Lab</title>
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
        <span class="level-badge">Level 10</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-expert">Expert</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-variable">$tpl</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'tpl'</span>];

<span class="php-comment">// WAF layer 1 — keyword blocklist</span>
<span class="php-keyword">if</span> (<span class="php-function">preg_match</span>(<span class="php-string">'/system|exec|shell_exec|passthru|call_user_func/i'</span>, <span class="php-variable">$tpl</span>))
    <span class="php-keyword">die</span>(<span class="php-string">'Layer 1'</span>);
<span class="php-comment">// WAF layer 2 — character blocklist</span>
<span class="php-keyword">if</span> (<span class="php-function">strpbrk</span>(<span class="php-variable">$tpl</span>, <span class="php-string">"'\"`"</span>) !== <span class="php-keyword">false</span>)
    <span class="php-keyword">die</span>(<span class="php-string">'Layer 2'</span>);
<span class="php-comment">// WAF layer 3 — non-recursive delimiter stripper (one pass)</span>
<span class="vuln-line"><span class="php-variable">$tpl</span> = <span class="php-function">strip_outer_delims</span>(<span class="php-variable">$tpl</span>); <span class="php-comment">// removes first {{ and last }}</span></span>

<span class="php-variable">$out</span> = <span class="php-function">render_template</span>(<span class="php-variable">$tpl</span>); <span class="php-comment">// same eval() engine (statements allowed)</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; Each layer is individually bypassable, and they do not
                cover each other. Nest the delimiters to beat layer 3, drop all quotes/backticks for layer 2,
                and assemble the function name from <code>chr()</code> codes into a variable function for
                layer 1 — one payload defeats all three.
            </div>
        </div>

        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The final boss: every previous defence stacked into one WAF — keyword blocklist,
                character blocklist, and the non-recursive delimiter stripper.</p>
                <p>Combine the techniques you have learned into a single vector that survives all three
                layers and executes a command.</p>
            </div>

            <form method="get" action="level10.php">
                <div class="form-group">
                    <label class="form-label" for="tpl_input">Template (tpl parameter)</label>
                    <input
                        type="text"
                        id="tpl_input"
                        name="tpl"
                        class="form-control"
                        placeholder="nest + chr() + variable function"
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Render Template</button>
                    <?php if ($input !== ''): ?>
                    <a href="level10.php" class="btn btn-secondary">Clear</a>
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
            <?php elseif ($input !== '' && $run['blocked']): ?>
            <div class="message error">Stopped by <?= htmlspecialchars($run['reason']) ?>. Beat every layer at once — nest the braces, drop quotes/backticks, and build the name with <code>chr()</code>.</div>
            <?php elseif ($input !== ''): ?>
            <div class="message error">Survived the WAF but no command ran. See the final hint for the full vector.</div>
            <?php endif; ?>

            <?php if ($input !== ''): ?>
            <div class="xss-output-section">
                <h4>Live Output (server-rendered template):</h4>
                <?php if ($run['blocked']): ?>
                    <div class="output-box" style="color:#f87171;">[WAF BLOCKED] <?= htmlspecialchars($run['reason']) ?></div>
                <?php else: ?>
                    <div class="output-box"><?= trim($run['rendered']) !== '' ? htmlspecialchars($run['rendered']) : '(empty result)' ?></div>
                <?php endif; ?>
                <p class="xss-sandbox-note">
                    All three WAF layers run before the engine; this box shows what executed if your vector survived.
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
        <a href="submit.php" class="btn btn-secondary">Finish &rarr;</a>
    </div>

</div><!-- /.container -->
</body>
</html>
