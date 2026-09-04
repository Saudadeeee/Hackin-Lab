<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 4;
$levelTitle = 'Local File Disclosure';
$prevLevel  = 3;
$nextLevel  = 5;

$input = $_GET['tpl'] ?? '';

$run  = ['blocked' => false, 'reason' => '', 'rendered' => '', 'executed' => false];
$flag = '';
$flagMessage = '';

if ($input !== '') {
    $run = run_ssti_level($levelId, $input);
    if (ssti_flag_earned($levelId, $input, $run)) {
        $flag        = get_flag_for_level($levelId);
        $flagMessage = 'You disclosed the secret file /var/secret/flag.txt through the template.';
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
    <title>Level 4 — Local File Disclosure | SSTI Lab</title>
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
        <span class="level-badge">Level 4</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">function</span> <span class="php-function">render_template</span>(<span class="php-variable">$tpl</span>) {
    <span class="php-keyword">return</span> <span class="php-function">preg_replace_callback</span>(<span class="php-string">'/\{\{(.+?)\}\}/s'</span>, <span class="php-keyword">function</span> (<span class="php-variable">$m</span>) {
        <span class="php-variable">$expr</span> = <span class="php-function">trim</span>(<span class="php-variable">$m</span>[1]);
<span class="vuln-line">        <span class="php-keyword">return</span> <span class="php-function">eval</span>(<span class="php-string">'return ('</span> . <span class="php-variable">$expr</span> . <span class="php-string">');'</span>); <span class="php-comment">// file readers run too</span></span>
    }, <span class="php-variable">$tpl</span>);
}

<span class="php-comment">// Secret baked into the image at /var/secret/flag.txt</span>
<span class="php-variable">$out</span> = <span class="php-function">render_template</span>(<span class="php-variable">$_GET</span>[<span class="php-string">'tpl'</span>]);</code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp; Arbitrary function execution includes file-reading
                functions. <code>file_get_contents()</code> returns a file's contents as a string,
                which the template happily renders — disclosing anything the web user can read.
            </div>
        </div>

        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>A secret lives on disk at <code>/var/secret/flag.txt</code>, outside the web root and
                unreachable by URL. But the template engine runs as the same OS user the file allows.</p>
                <p>Read the secret through a <code>{{ ... }}</code> expression. The verifier confirms the
                real file contents appear in your output.</p>
            </div>

            <form method="get" action="level4.php">
                <div class="form-group">
                    <label class="form-label" for="tpl_input">Template (tpl parameter)</label>
                    <input
                        type="text"
                        id="tpl_input"
                        name="tpl"
                        class="form-control"
                        placeholder="e.g. {{ file_get_contents('/etc/hostname') }}"
                        value="<?= htmlspecialchars($input) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Render Template</button>
                    <?php if ($input !== ''): ?>
                    <a href="level4.php" class="btn btn-secondary">Clear</a>
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
            <div class="message error">The secret file was not disclosed. Try <code>{{ file_get_contents('/var/secret/flag.txt') }}</code>.</div>
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
                    This is the <strong>real</strong> content the engine read off the server's disk.
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
