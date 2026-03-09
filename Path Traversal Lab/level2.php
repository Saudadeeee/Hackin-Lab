<?php
require_once __DIR__ . '/helpers.php';

$levelNum  = 2;
$_flag_result = handle_inline_flag_submit($levelNum);
$output    = null;
$flagFound = false;
$flagValue = '';

if (isset($_GET['page'])) {
    $page = $_GET['page'];
    // --- VULNERABLE CODE (same as shown in source panel) ---
    // We use readfile() instead of include() to avoid executing arbitrary PHP,
    // but the path traversal / LFI behaviour is identical.
    ob_start();
    @readfile($page);
    $content = ob_get_clean();
    // -------------------------------------------------------
    if ($content === '' || $content === false) {
        $output = '[Error: Could not read file or file is empty]';
    } else {
        $output = $content;
        if (strpos($output, 'FLAG{') !== false) {
            $flagFound = true;
            $flagValue = get_flag_for_level($levelNum);
            mark_level_completed($levelNum);
        }
    }
} else {
    $output = @file_get_contents('/var/www/html/files/welcome.txt') ?: 'Welcome to Path Traversal Lab!';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 2 - Local File Inclusion | Path Traversal Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
<div class="header">
    <div>
        <h1>Level 2 &mdash; Local File Inclusion without Restriction</h1>
        <p>Easy &bull; include() with no path restriction — full filesystem access</p>
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
<span class="php-variable">$page</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'page'</span>] ?? <span class="php-string">'home'</span>;
<span class="vuln-line"><span class="php-function">include</span>(<span class="php-variable">$page</span>);  <span class="php-comment">// VULNERABLE: no path restriction</span></span>
<span class="php-keyword">?&gt;</span></code>
            </div>
            <div style="margin-top:1rem; font-size:0.85rem; color:var(--text-muted); line-height:1.7;">
                <strong style="color:var(--text);">What to look for:</strong><br>
                <code>include()</code> is called with the raw <code>$_GET['page']</code> value.
                There is <strong>no base path prefix</strong>, no extension check, and no
                sanitization — any absolute path on the filesystem is accessible.<br><br>
                <strong style="color:var(--text);">Goal:</strong>
                Read <code>/var/secret/level2_flag.txt</code>
            </div>
        </div>

        <!-- RIGHT: Challenge Panel -->
        <div class="challenge-panel">
            <h3>Challenge</h3>
            <div class="scenario">
                <strong>Scenario:</strong> A simple page router passes the <code>page</code>
                GET parameter directly to <code>include()</code>. No path is prepended — supply
                an absolute path to any file on the server.
            </div>

            <form method="GET" action="level2.php">
                <div class="form-group">
                    <label for="page">Page parameter (<code>?page=</code>)</label>
                    <input type="text" id="page" name="page" class="form-control"
                           placeholder="e.g. /var/www/html/pages/home.php"
                           value="<?= htmlspecialchars($_GET['page'] ?? '') ?>">
                </div>
                <button type="submit" class="btn btn-primary">Load Page</button>
            </form>

            <?php if ($output !== null): ?>
            <div style="margin-top:1rem;">
                <label style="font-size:0.82rem; color:var(--text-muted);">Output:</label>
                <div class="output-box <?= empty(trim($output)) ? 'empty' : '' ?>"><?= htmlspecialchars($output) ?></div>
            </div>
            <?php endif; ?>

            <?php if ($flagFound): ?>
            <div class="message success">Flag captured! The included file contained a FLAG{} string.</div>
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
        <span style="color:var(--text-muted); font-size:0.85rem;">Level 2 / 10</span>
        <a href="level1.php" class="prev-link">&larr; Previous</a>
        <a href="index.php" class="nav-link">Home</a>
        <a href="level3.php" class="next-link">Next Level &rarr;</a>
        <a href="submit.php" class="nav-link">Submit Flag</a>
    </div>
</div>
</body>
</html>
