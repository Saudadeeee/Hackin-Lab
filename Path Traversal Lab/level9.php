<?php
require_once __DIR__ . '/helpers.php';

$levelNum  = 9;
$_flag_result = handle_inline_flag_submit($levelNum);
$output    = null;
$flagFound = false;
$flagValue = '';
$blocked   = false;

if (isset($_GET['file'])) {
    $file = $_GET['file'];
    // --- VULNERABLE CODE (same as shown in source panel) ---
    if (strpos($file, '/etc/passwd') !== false || strpos($file, '/etc/shadow') !== false) {
        $blocked = true;
        $output  = '[Blocked: sensitive system file!]';
    } else {
        $content = @file_get_contents('/var/www/html/' . $file);
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
    <title>Level 9 - /proc Filesystem | Path Traversal Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
<div class="header">
    <div>
        <h1>Level 9 &mdash; Linux /proc Filesystem via Path Traversal</h1>
        <p>Hard &bull; A blacklist blocks only two specific paths — many others remain accessible</p>
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
<span class="php-variable">$file</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'file'</span>] ?? <span class="php-string">'files/welcome.txt'</span>;
<span class="php-comment">// Only block dangerous paths</span>
<span class="vuln-line"><span class="php-keyword">if</span> (<span class="php-function">strpos</span>(<span class="php-variable">$file</span>, <span class="php-string">'/etc/passwd'</span>) !== <span class="php-keyword">false</span> || <span class="php-function">strpos</span>(<span class="php-variable">$file</span>, <span class="php-string">'/etc/shadow'</span>) !== <span class="php-keyword">false</span>) {</span>
<span class="vuln-line">    <span class="php-function">die</span>(<span class="php-string">"Blocked: sensitive system file!"</span>);</span>
<span class="vuln-line">}</span>
<span class="php-variable">$content</span> = <span class="php-function">file_get_contents</span>(<span class="php-string">'/var/www/html/'</span> . <span class="php-variable">$file</span>);
<span class="php-function">echo</span> <span class="php-string">"&lt;pre&gt;"</span> . <span class="php-function">htmlspecialchars</span>(<span class="php-variable">$content</span> ?: <span class="php-string">'File not found'</span>) . <span class="php-string">"&lt;/pre&gt;"</span>;
<span class="php-keyword">?&gt;</span></code>
            </div>
            <div style="margin-top:1rem; font-size:0.85rem; color:var(--text-muted); line-height:1.7;">
                <strong style="color:var(--text);">What to look for:</strong><br>
                The blacklist only blocks <code>/etc/passwd</code> and <code>/etc/shadow</code>.
                Every other path on the filesystem — including <code>/var/secret/</code> and
                the Linux <code>/proc/</code> virtual filesystem — is accessible.<br><br>
                <strong style="color:var(--text);">Primary goal:</strong>
                Traverse to <code>/var/secret/level9_flag.txt</code>.<br>
                <strong style="color:var(--text);">Bonus:</strong>
                Read <code>/proc/self/environ</code> to explore environment variables,
                or <code>/proc/self/cmdline</code> to see the running process.
            </div>
        </div>

        <!-- RIGHT: Challenge Panel -->
        <div class="challenge-panel">
            <h3>Challenge</h3>
            <div class="scenario">
                <strong>Scenario:</strong> A developer blocked "the two most sensitive files"
                (<code>/etc/passwd</code> and <code>/etc/shadow</code>). This leaves virtually
                the entire filesystem accessible — including <code>/proc/self/environ</code>
                and the secret flag directory.
            </div>

            <form method="GET" action="level9.php">
                <div class="form-group">
                    <label for="file">File parameter (<code>?file=</code>)</label>
                    <input type="text" id="file" name="file" class="form-control"
                           placeholder="e.g. files/welcome.txt or ../../var/secret/..."
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
            <div class="message success">Flag captured! The blacklist did not protect <code>/var/secret/</code>.</div>
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
        <span style="color:var(--text-muted); font-size:0.85rem;">Level 9 / 10</span>
        <a href="level8.php" class="prev-link">&larr; Previous</a>
        <a href="index.php" class="nav-link">Home</a>
        <a href="level10.php" class="next-link">Next Level &rarr;</a>
        <a href="submit.php" class="nav-link">Submit Flag</a>
    </div>
</div>
</body>
</html>
