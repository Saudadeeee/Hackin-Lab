<?php
require_once __DIR__ . '/helpers.php';

$levelNum = 1;
$_flag_result = handle_inline_flag_submit($levelNum);
$output   = null;
$flagFound = false;
$flagValue = '';

if (isset($_GET['file'])) {
    $file = $_GET['file'];
    // --- VULNERABLE CODE (same as shown in source panel) ---
    $base    = '/var/www/html/files/';
    $content = @file_get_contents($base . $file);
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
} else {
    // Default: show welcome.txt
    $output = @file_get_contents('/var/www/html/files/welcome.txt') ?: 'Welcome to Path Traversal Lab!';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 1 - Basic Directory Traversal | Path Traversal Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
<div class="header">
    <div>
        <h1>Level 1 &mdash; Basic Directory Traversal</h1>
        <p>Easy &bull; Read the source code and craft a path traversal payload</p>
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
<span class="php-variable">$base</span> = <span class="php-string">'/var/www/html/files/'</span>;
<span class="vuln-line"><span class="php-variable">$content</span> = <span class="php-function">file_get_contents</span>(<span class="php-variable">$base</span> . <span class="php-variable">$file</span>);   <span class="php-comment">// VULNERABLE LINE</span></span>
<span class="php-function">echo</span> <span class="php-function">nl2br</span>(<span class="php-function">htmlspecialchars</span>(<span class="php-variable">$content</span>));
<span class="php-keyword">?&gt;</span></code>
            </div>
            <div style="margin-top:1rem; font-size:0.85rem; color:var(--text-muted); line-height:1.7;">
                <strong style="color:var(--text);">What to look for:</strong><br>
                The <code>$file</code> parameter from <code>$_GET</code> is appended directly to
                <code>/var/www/html/files/</code> with no sanitization or validation.
                There is no restriction on what characters appear in <code>$file</code>.<br><br>
                <strong style="color:var(--text);">Goal:</strong>
                Read <code>/var/secret/level1_flag.txt</code>
            </div>
        </div>

        <!-- RIGHT: Challenge Panel -->
        <div class="challenge-panel">
            <h3>Challenge</h3>
            <div class="scenario">
                <strong>Scenario:</strong> A file viewer appends the <code>file</code> parameter
                directly to a base path and reads it. No input sanitization is applied.
                Traverse out of <code>/var/www/html/files/</code> to read the flag.
            </div>

            <form method="GET" action="level1.php">
                <div class="form-group">
                    <label for="file">File parameter (<code>?file=</code>)</label>
                    <input type="text" id="file" name="file" class="form-control"
                           placeholder="e.g. welcome.txt"
                           value="<?= htmlspecialchars($_GET['file'] ?? 'welcome.txt') ?>">
                </div>
                <button type="submit" class="btn btn-primary">Read File</button>
            </form>

            <?php if ($output !== null): ?>
            <div style="margin-top:1rem;">
                <label style="font-size:0.82rem; color:var(--text-muted);">Output:</label>
                <div class="output-box <?= empty(trim($output)) ? 'empty' : '' ?>"><?= htmlspecialchars($output) ?></div>
            </div>
            <?php endif; ?>

            <?php if ($flagFound): ?>
            <div class="message success">Flag captured! The file contained a FLAG{} string.</div>
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
        <span style="color:var(--text-muted); font-size:0.85rem;">Level 1 / 10</span>
        <a href="index.php" class="nav-link">Home</a>
        <a href="level2.php" class="next-link">Next Level &rarr;</a>
        <a href="submit.php" class="nav-link">Submit Flag</a>
    </div>
</div>
</body>
</html>
