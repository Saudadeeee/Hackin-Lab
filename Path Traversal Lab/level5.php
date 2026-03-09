<?php
require_once __DIR__ . '/helpers.php';

$levelNum  = 5;
$_flag_result = handle_inline_flag_submit($levelNum);
$output    = null;
$flagFound = false;
$flagValue = '';
$blocked   = false;

if (isset($_GET['file'])) {
    $file = $_GET['file'];
    // --- VULNERABLE CODE (same as shown in source panel) ---
    if (substr($file, -4) !== '.txt') {
        $blocked = true;
        $output  = '[Error: Only .txt files allowed!]';
    } else {
        $content = @file_get_contents('/var/www/html/files/' . $file);
        // -------------------------------------------------------
        if ($content === false) {
            $output = '[Error: Could not read file]';
        } else {
            $output = $content;
            if (strpos($output, 'FLAG{') !== false) {
                $flagFound = true;
                $flagValue = get_flag_for_level($levelNum);
                mark_level_completed($levelNum);
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 5 - Extension Check Bypass | Path Traversal Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
<div class="header">
    <div>
        <h1>Level 5 &mdash; Bypass Extension Validation</h1>
        <p>Medium &bull; Only .txt files are "allowed" — but that doesn't prevent traversal</p>
    </div>
    <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
        <a href="index.php" class="back-btn">All Levels</a>
        <a href="submit.php" class="submit-btn">Submit Flag</a>
    </div>
</div>

<div class="container">
    <div class="challenge-layout">

        <!-- LEFT: Source Code Panel -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <code><span class="php-keyword">&lt;?php</span>
<span class="php-variable">$file</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'file'</span>] ?? <span class="php-string">'welcome.txt'</span>;
<span class="vuln-line"><span class="php-keyword">if</span> (<span class="php-function">substr</span>(<span class="php-variable">$file</span>, -4) !== <span class="php-string">'.txt'</span>) {    <span class="php-comment">// Only checks extension!</span></span>
<span class="vuln-line">    <span class="php-function">die</span>(<span class="php-string">"Error: Only .txt files allowed!"</span>);</span>
<span class="vuln-line">}</span>
<span class="php-variable">$content</span> = <span class="php-function">file_get_contents</span>(<span class="php-string">'/var/www/html/files/'</span> . <span class="php-variable">$file</span>);  <span class="php-comment">// VULNERABLE</span>
<span class="php-function">echo</span> <span class="php-function">nl2br</span>(<span class="php-function">htmlspecialchars</span>(<span class="php-variable">$content</span>));
<span class="php-keyword">?&gt;</span></code>
            </div>
            <div style="margin-top:1rem; font-size:0.85rem; color:var(--text-muted); line-height:1.7;">
                <strong style="color:var(--text);">What to look for:</strong><br>
                The check <code>substr($file, -4) !== '.txt'</code> only validates that the
                input <em>ends with</em> <code>.txt</code>. It does <strong>not</strong> check
                for <code>../</code> sequences or restrict directory traversal in any way.<br><br>
                A path traversal payload that ends in <code>.txt</code> passes the check completely.<br><br>
                <strong style="color:var(--text);">Goal:</strong>
                Read <code>/var/secret/level5_flag.txt</code>
            </div>
        </div>

        <!-- RIGHT: Challenge Panel -->
        <div class="challenge-panel">
            <h3>Challenge</h3>
            <div class="scenario">
                <strong>Scenario:</strong> A developer restricted file access to <code>.txt</code>
                files only by checking the last 4 characters. They forgot that a traversal payload
                targeting a <code>.txt</code> file satisfies both the extension check and
                the traversal goal simultaneously.
            </div>

            <form method="GET" action="level5.php">
                <div class="form-group">
                    <label for="file">File parameter (<code>?file=</code>)</label>
                    <input type="text" id="file" name="file" class="form-control"
                           placeholder="Must end in .txt..."
                           value="<?= htmlspecialchars($_GET['file'] ?? '') ?>">
                </div>
                <button type="submit" class="btn btn-primary">Read File</button>
            </form>

            <?php if ($output !== null): ?>
            <div style="margin-top:1rem;">
                <label style="font-size:0.82rem; color:var(--text-muted);">Output:</label>
                <div class="output-box <?= (empty(trim($output)) || $blocked) ? 'empty' : '' ?>"><?= htmlspecialchars($output) ?></div>
            </div>
            <?php endif; ?>

            <?php if ($flagFound): ?>
            <div class="message success">Flag captured! Extension check bypassed — path traversal succeeded.</div>
            <div class="flag-display"><?= htmlspecialchars($flagValue) ?></div>
            <p style="font-size:0.82rem; color:var(--text-muted); margin-top:0.5rem;">
                Submit this flag at <a href="submit.php" style="color:var(--primary);">submit.php</a> to record your progress.
            </p>
            <?php endif; ?>
        </div>
    </div>

    <?= render_hint_section(get_level_hints($levelNum)) ?>
    <?= render_inline_flag_form($levelNum, $_flag_result) ?>

    <div class="navigation">
        <span style="color:var(--text-muted); font-size:0.85rem;">Level 5 / 10</span>
        <a href="level4.php" class="prev-link">&larr; Previous</a>
        <a href="index.php" class="nav-link">Home</a>
        <a href="level6.php" class="next-link">Next Level &rarr;</a>
        <a href="submit.php" class="nav-link">Submit Flag</a>
    </div>
</div>
</body>
</html>
