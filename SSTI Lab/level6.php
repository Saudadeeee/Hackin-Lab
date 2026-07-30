<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 6;
$levelTitle = 'Keyword Blocklist Bypass';
$prevLevel  = 5;
$nextLevel  = 7;

$input = $_GET['tpl'] ?? '';

$run  = ['blocked' => false, 'reason' => '', 'rendered' => '', 'executed' => false];
$flag = '';
$flagMessage = '';

if ($input !== '') {
    $run = run_ssti_level($levelId, $input);
    if (ssti_flag_earned($levelId, $input, $run)) {
        $flag        = get_flag_for_level($levelId);
        $flagMessage = 'You reached RCE without ever naming a blocked function.';
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
    <title>Level 6 — Keyword Blocklist Bypass | SSTI Lab</title>
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
        <span class="level-badge">Level 6</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-variable">$tpl</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'tpl'</span>];

<span class="php-comment">// "Defence": reject dangerous function names by substring.</span>
<span class="php-keyword">if</span> (<span class="php-function">preg_match</span>(<span class="php-string">'/system|exec|shell_exec|passthru/i'</span>, <span class="php-variable">$tpl</span>)) {
    <span class="php-keyword">die</span>(<span class="php-string">'Blocked keyword'</span>);
}

<span class="php-keyword">function</span> <span class="php-function">render_template</span>(<span class="php-variable">$tpl</span>) {
    <span class="php-keyword">return</span> <span class="php-function">preg_replace_callback</span>(<span class="php-string">'/\{\{(.+?)\}\}/s'</span>, <span class="php-keyword">function</span> (<span class="php-variable">$m</span>) {
<span class="vuln-line">        <span class="php-keyword">return</span> <span class="php-function">eval</span>(<span class="php-string">'return ('</span> . <span class="php-function">trim</span>(<span class="php-variable">$m</span>[1]) . <span class="php-string">');'</span>);</span>
    }, <span class="php-variable">$tpl</span>);
}
<span class="php-variable">$out</span> = <span class="php-function">render_template</span>(<span class="php-variable">$tpl</span>);</code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; The blocklist only matches four <em>literal</em>
                substrings. The backtick operator names no function, and a split string like
                <code>'sys'.'tem'</code> never contains the substring <code>system</code> — so both slip past.
            </div>
        </div>

        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>Someone bolted on a keyword filter after the last incident. It rejects any request whose
                template contains <code>system</code>, <code>exec</code>, <code>shell_exec</code> or
                <code>passthru</code>.</p>
                <p>Reach RCE anyway — without those substrings ever appearing in your input.</p>
            </div>

            <form method="get" action="level6.php">
                <div class="form-group">
                    <label class="form-label" for="tpl_input">Template (tpl parameter)</label>
                    <input
                        type="text"
                        id="tpl_input"
                        name="tpl"
                        class="form-control"
                        placeholder="e.g. {{ `id` }}"
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Render Template</button>
                    <?php if ($input !== ''): ?>
                    <a href="level6.php" class="btn btn-secondary">Clear</a>
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
            <div class="message error">The keyword filter rejected your input. Avoid the blocked substrings entirely — try backticks or a split-string call.</div>
            <?php elseif ($input !== ''): ?>
            <div class="message error">No command execution detected. Try <code>{{ `id` }}</code> or <code>{{ call_user_func('sys'.'tem','id') }}</code>.</div>
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
                    The keyword filter runs first; this box shows what the engine executed if the input survived.
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
