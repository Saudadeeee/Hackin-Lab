<?php
require_once __DIR__ . '/helpers.php';

$levelNum  = 10;
$_flag_result = handle_inline_flag_submit($levelNum);
$output    = null;
$flagFound = false;
$flagValue = '';
$blocked   = false;

if (isset($_GET['file'])) {
    $file = $_GET['file'];
    // --- VULNERABLE CODE (same as shown in source panel) ---
    $file = str_replace('../', '', $file);              // Remove ../
    $file = str_replace('..\\', '', $file);             // Remove ..\
    if (strpos($file, '/etc/') !== false) {
        $blocked = true;
        $output  = '[Blocked! /etc/ is not allowed.]';
    } elseif (strpos($file, '/proc/') !== false) {
        $blocked = true;
        $output  = '[Blocked! /proc/ is not allowed.]';
    } else {
        $content = @file_get_contents('/var/www/html/files/' . $file);
        // -------------------------------------------------------
        if ($content === false) {
            $output = '[Error: File not found]';
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
    <title>Level 10 - Multi-Filter Bypass | Path Traversal Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
<div class="header">
    <div>
        <h1>Level 10 &mdash; Multi-Filter Path Traversal</h1>
        <p>Expert &bull; Stack multiple bypass techniques to defeat layered defences</p>
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
<span class="vuln-line"><span class="php-variable">$file</span> = <span class="php-function">str_replace</span>(<span class="php-string">'../'</span>, <span class="php-string">''</span>, <span class="php-variable">$file</span>);              <span class="php-comment">// Remove ../</span></span>
<span class="vuln-line"><span class="php-variable">$file</span> = <span class="php-function">str_replace</span>(<span class="php-string">'..\\'</span>, <span class="php-string">''</span>, <span class="php-variable">$file</span>);             <span class="php-comment">// Remove ..\</span></span>
<span class="vuln-line"><span class="php-keyword">if</span> (<span class="php-function">strpos</span>(<span class="php-variable">$file</span>, <span class="php-string">'/etc/'</span>) !== <span class="php-keyword">false</span>) <span class="php-function">die</span>(<span class="php-string">"Blocked!"</span>);  <span class="php-comment">// Block /etc/</span></span>
<span class="vuln-line"><span class="php-keyword">if</span> (<span class="php-function">strpos</span>(<span class="php-variable">$file</span>, <span class="php-string">'/proc/'</span>) !== <span class="php-keyword">false</span>) <span class="php-function">die</span>(<span class="php-string">"Blocked!"</span>); <span class="php-comment">// Block /proc/</span></span>
<span class="php-variable">$content</span> = <span class="php-function">file_get_contents</span>(<span class="php-string">'/var/www/html/files/'</span> . <span class="php-variable">$file</span>);
<span class="php-function">echo</span> <span class="php-function">nl2br</span>(<span class="php-function">htmlspecialchars</span>(<span class="php-variable">$content</span> ?: <span class="php-string">'Not found'</span>));
<span class="php-keyword">?&gt;</span></code>
            </div>
            <div style="margin-top:1rem; font-size:0.85rem; color:var(--text-muted); line-height:1.7;">
                <strong style="color:var(--text);">What to look for:</strong><br>
                Four filters are applied in sequence:<br>
                1. <code>str_replace('../', '')</code> — non-recursive removal of <code>../</code><br>
                2. <code>str_replace('..\', '')</code> — same for Windows-style backslash<br>
                3. Block if <code>/etc/</code> appears in the result<br>
                4. Block if <code>/proc/</code> appears in the result<br><br>
                The target is <code>/var/secret/</code> — it is <strong>not</strong> in the
                blocklist. Use the <code>....//</code> technique (from Level 4) to bypass
                filter 1, then target a path that avoids <code>/etc/</code> and <code>/proc/</code>.<br><br>
                <strong style="color:var(--text);">Goal:</strong>
                Read <code>/var/secret/level10_flag.txt</code>
            </div>
        </div>

        <!-- RIGHT: Challenge Panel -->
        <div class="challenge-panel">
            <h3>Challenge</h3>
            <div class="scenario">
                <strong>Scenario:</strong> The final boss — four layered defences. Analyse each
                filter independently, identify what paths survive all filters, and chain bypass
                techniques to reach the flag. Remember: <code>/var/secret/</code> is not on
                any blocklist.
            </div>

            <form method="GET" action="level10.php">
                <div class="form-group">
                    <label for="file">File parameter (<code>?file=</code>)</label>
                    <input type="text" id="file" name="file" class="form-control"
                           placeholder="Bypass all filters..."
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
            <div class="message success">
                Congratulations! You have defeated all 10 levels of the Path Traversal Lab!
                The multi-layer filter was no match for a methodical approach.
            </div>
            <div class="flag-display"><?= htmlspecialchars($flagValue) ?></div>
            <p style="font-size:0.82rem; color:var(--text-muted); margin-top:0.5rem;">
                Submit this final flag at <a href="submit.php" style="color:var(--primary);">submit.php</a> to complete the lab!
            </p>
            <?php endif; ?>
        </div>
    </div>

    <?= render_hint_section(get_level_hints($levelNum)) ?>
    <?= render_inline_flag_form($levelNum, $_flag_result) ?>

    <div class="navigation">
        <span style="color:var(--text-muted); font-size:0.85rem;">Level 10 / 10 &mdash; Final Level</span>
        <a href="level9.php" class="prev-link">&larr; Previous</a>
        <a href="index.php" class="nav-link">Home</a>
        <a href="submit.php" class="next-link">Submit Final Flag</a>
    </div>
</div>
</body>
</html>
