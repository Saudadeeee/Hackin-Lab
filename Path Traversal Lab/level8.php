<?php
require_once __DIR__ . '/helpers.php';

$levelNum  = 8;
$_flag_result = handle_inline_flag_submit($levelNum);
$output    = null;
$flagFound = false;
$flagValue = '';
$blocked   = false;

if (isset($_GET['file'])) {
    $file = $_GET['file'];
    // --- VULNERABLE CODE (same as shown in source panel) ---
    $base     = '/var/www/html/files/';
    $fullpath = $base . $file;
    // "Security check": verify path starts with base directory
    if (substr($fullpath, 0, strlen($base)) !== $base) {
        $blocked = true;
        $output  = '[Security check failed: access denied!]';
    } else {
        $content = @file_get_contents($fullpath);
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
    <title>Level 8 - Useless Security Check | Path Traversal Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
<div class="header">
    <div>
        <h1>Level 8 &mdash; Spot the Useless Security Check</h1>
        <p>Hard &bull; There is a "security check" in the code — is it actually effective?</p>
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
<span class="php-variable">$file</span>     = <span class="php-variable">$_GET</span>[<span class="php-string">'file'</span>] ?? <span class="php-string">'welcome.txt'</span>;
<span class="php-variable">$base</span>     = <span class="php-string">'/var/www/html/files/'</span>;
<span class="php-variable">$fullpath</span> = <span class="php-variable">$base</span> . <span class="php-variable">$file</span>;
<span class="php-comment">// "Security check": verify path starts with base directory</span>
<span class="vuln-line"><span class="php-keyword">if</span> (<span class="php-function">substr</span>(<span class="php-variable">$fullpath</span>, 0, <span class="php-function">strlen</span>(<span class="php-variable">$base</span>)) !== <span class="php-variable">$base</span>) {</span>
<span class="vuln-line">    <span class="php-function">die</span>(<span class="php-string">"Security check failed: access denied!"</span>);</span>
<span class="vuln-line">}</span>
<span class="php-variable">$content</span> = <span class="php-function">file_get_contents</span>(<span class="php-variable">$fullpath</span>);  <span class="php-comment">// VULNERABLE</span>
<span class="php-function">echo</span> <span class="php-function">nl2br</span>(<span class="php-function">htmlspecialchars</span>(<span class="php-variable">$content</span>));
<span class="php-keyword">?&gt;</span></code>
            </div>
            <div style="margin-top:1rem; font-size:0.85rem; color:var(--text-muted); line-height:1.7;">
                <strong style="color:var(--text);">What to look for:</strong><br>
                Trace through the logic very carefully:<br>
                1. <code>$fullpath = $base . $file</code> — <code>$base</code> is hardcoded.<br>
                2. <code>substr($fullpath, 0, strlen($base))</code> — extracts the first
                <code>strlen($base)</code> characters of <code>$fullpath</code>.<br>
                3. Since <code>$fullpath</code> is constructed as <code>$base . $file</code>,
                the first <code>strlen($base)</code> characters are <em>always</em>
                exactly <code>$base</code>.<br>
                4. The condition is <strong>always false</strong> — the security check
                never triggers.<br><br>
                <strong style="color:var(--text);">Goal:</strong>
                Recognise that the check is logically useless. Use plain path traversal
                to read <code>/var/secret/level8_flag.txt</code>.
            </div>
        </div>

        <!-- RIGHT: Challenge Panel -->
        <div class="challenge-panel">
            <h3>Challenge</h3>
            <div class="scenario">
                <strong>Scenario:</strong> A developer added a security check to ensure
                the resolved path stays within the base directory. But they checked
                <code>$fullpath</code> — which they themselves constructed by prepending
                <code>$base</code>. The check is logically circular and completely useless.
            </div>

            <form method="GET" action="level8.php">
                <div class="form-group">
                    <label for="file">File parameter (<code>?file=</code>)</label>
                    <input type="text" id="file" name="file" class="form-control"
                           placeholder="e.g. welcome.txt or ../../../../..."
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
            <div class="message success">Flag captured! The security check was indeed useless — path traversal worked.</div>
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
        <span style="color:var(--text-muted); font-size:0.85rem;">Level 8 / 10</span>
        <a href="level7.php" class="prev-link">&larr; Previous</a>
        <a href="index.php" class="nav-link">Home</a>
        <a href="level9.php" class="next-link">Next Level &rarr;</a>
        <a href="submit.php" class="nav-link">Submit Flag</a>
    </div>
</div>
</body>
</html>
