<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 7;
$levelTitle = 'Character Blocklist Bypass';
$prevLevel  = 6;
$nextLevel  = 8;

$input = $_GET['tpl'] ?? '';

$run  = ['blocked' => false, 'reason' => '', 'rendered' => '', 'executed' => false];
$flag = '';
$flagMessage = '';

if ($input !== '') {
    $run = run_ssti_level($levelId, $input);
    if (ssti_flag_earned($levelId, $input, $run)) {
        $flag        = get_flag_for_level($levelId);
        $flagMessage = 'You built a command without a single quote or backtick.';
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
    <title>Level 7 — Character Blocklist Bypass | SSTI Lab</title>
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
        <span class="level-badge">Level 7</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-variable">$tpl</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'tpl'</span>];

<span class="php-comment">// "Defence": ban string literals and the backtick operator.</span>
<span class="php-keyword">if</span> (<span class="php-function">strpbrk</span>(<span class="php-variable">$tpl</span>, <span class="php-string">"'\"`"</span>) !== <span class="php-keyword">false</span>) {
    <span class="php-keyword">die</span>(<span class="php-string">'Blocked character'</span>);
}

<span class="php-keyword">function</span> <span class="php-function">render_template</span>(<span class="php-variable">$tpl</span>) {
    <span class="php-keyword">return</span> <span class="php-function">preg_replace_callback</span>(<span class="php-string">'/\{\{(.+?)\}\}/s'</span>, <span class="php-keyword">function</span> (<span class="php-variable">$m</span>) {
<span class="vuln-line">        <span class="php-keyword">return</span> <span class="php-function">eval</span>(<span class="php-string">'return ('</span> . <span class="php-function">trim</span>(<span class="php-variable">$m</span>[1]) . <span class="php-string">');'</span>);</span>
    }, <span class="php-variable">$tpl</span>);
}
<span class="php-variable">$out</span> = <span class="php-function">render_template</span>(<span class="php-variable">$tpl</span>);</code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; Blocking quotes and backticks removes string literals,
                but not string <em>construction</em>. <code>chr()</code> builds characters from integers,
                and a numeric-key superglobal like <code>$_GET[0]</code> carries data with no quotes at all.
            </div>
        </div>

        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>The filter got stricter: it now rejects any input containing a single quote, a double
                quote, or a backtick. Writing <code>'id'</code> or using <code>`id`</code> is impossible.</p>
                <p>Execute a command without ever typing a quote. Build the string from
                <code>chr()</code> codes, or smuggle it in a numeric-key GET parameter.</p>
            </div>

            <form method="get" action="level7.php">
                <div class="form-group">
                    <label class="form-label" for="tpl_input">Template (tpl parameter)</label>
                    <input
                        type="text"
                        id="tpl_input"
                        name="tpl"
                        class="form-control"
                        placeholder="e.g. {{ system(chr(105).chr(100)) }}"
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <p style="font-size:0.75rem; color:var(--text-muted); margin:0.25rem 0 0;">
                    Tip: to use the <code>$_GET[0]</code> trick, append <code>&amp;0=id</code> to the URL after submitting.
                </p>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Render Template</button>
                    <?php if ($input !== ''): ?>
                    <a href="level7.php" class="btn btn-secondary">Clear</a>
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
            <div class="message error">A blocked character was found. Remove every quote and backtick — build strings with <code>chr()</code> instead.</div>
            <?php elseif ($input !== ''): ?>
            <div class="message error">No command execution detected. Try <code>{{ system(chr(105).chr(100)) }}</code>.</div>
            <?php endif; ?>

            <?php if ($input !== ''): ?>
            <div class="xss-output-section">
                <h4>Live Output (server-rendered template):</h4>
                <?php if ($run['blocked']): ?>
                    <div class="output-box" style="color:#b5766e;">[WAF BLOCKED] <?= htmlspecialchars($run['reason']) ?></div>
                <?php else: ?>
                    <div class="output-box"><?= trim($run['rendered']) !== '' ? htmlspecialchars($run['rendered']) : '(empty result)' ?></div>
                <?php endif; ?>
                <p class="xss-sandbox-note">
                    The character filter runs first; this box shows what the engine executed if the input survived.
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
