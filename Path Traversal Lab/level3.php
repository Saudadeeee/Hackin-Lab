<?php
require_once __DIR__ . '/helpers.php';

$levelNum  = 3;
$_flag_result = handle_inline_flag_submit($levelNum);
$output    = null;
$rawOutput = '';
$flagFound = false;
$flagValue = '';

if (isset($_GET['file'])) {
    $file = $_GET['file'];
    // --- VULNERABLE CODE (same as shown in source panel) ---
    if (strpos($file, '..') !== false) {
        $output = '[Traversal blocked! The string ".." is not allowed.]';
    } else {
        $content = @file_get_contents($file);
        if ($content === false) {
            $output = '[Error: Could not read file]';
        } else {
            $rawOutput = $content;
            $output    = $content;
            // Check both raw output and base64-decoded for a flag
            $decoded = @base64_decode($content, true);
            if (strpos($content, 'FLAG{') !== false || ($decoded !== false && strpos($decoded, 'FLAG{') !== false)) {
                $flagFound = true;
                $flagValue = get_flag_for_level($levelNum);
                mark_level_completed($levelNum);
            }
        }
    }
    // -------------------------------------------------------
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 3 - PHP Filter Wrapper | Path Traversal Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
<div class="header">
    <div>
        <h1>Level 3 &mdash; PHP Filter Wrapper Bypass</h1>
        <p>Medium &bull; The ".." sequence is blocked — but PHP stream wrappers are not</p>
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
<span class="php-keyword">if</span> (<span class="php-function">strpos</span>(<span class="php-variable">$file</span>, <span class="php-string">'..'</span>) !== <span class="php-keyword">false</span>) {
    <span class="php-function">die</span>(<span class="php-string">"Traversal blocked!"</span>);       <span class="php-comment">// BLOCKS ..</span>
}
<span class="vuln-line"><span class="php-variable">$content</span> = <span class="php-function">file_get_contents</span>(<span class="php-variable">$file</span>);  <span class="php-comment">// Still reads arbitrary files via wrappers</span></span>
<span class="php-function">echo</span> <span class="php-variable">$content</span>;
<span class="php-keyword">?&gt;</span></code>
            </div>
            <div style="margin-top:1rem; font-size:0.85rem; color:var(--text-muted); line-height:1.7;">
                <strong style="color:var(--text);">What to look for:</strong><br>
                The code checks for <code>..</code> but does not restrict PHP stream wrappers.
                <code>file_get_contents()</code> supports wrappers like <code>php://filter</code>
                that can read any file using an <em>absolute path</em> — no <code>..</code> needed.<br><br>
                <strong style="color:var(--text);">Goal:</strong>
                Use <code>php://filter</code> to read <code>/var/secret/level3_flag.txt</code>.
                The output will be base64-encoded; decode it to find the flag.
            </div>
        </div>

        <!-- RIGHT: Challenge Panel -->
        <div class="challenge-panel">
            <h3>Challenge</h3>
            <div class="scenario">
                <strong>Scenario:</strong> A developer added a check for <code>..</code> thinking it
                blocks path traversal entirely. However, PHP's built-in stream wrapper protocol
                <code>php://filter</code> reads arbitrary files via absolute paths — completely
                bypassing the <code>..</code> restriction.
            </div>

            <form method="GET" action="level3.php">
                <div class="form-group">
                    <label for="file">File parameter (<code>?file=</code>)</label>
                    <input type="text" id="file" name="file" class="form-control"
                           placeholder="e.g. php://filter/convert.base64-encode/resource=..."
                           value="<?= htmlspecialchars($_GET['file'] ?? '') ?>">
                </div>
                <button type="submit" class="btn btn-primary">Read File</button>
            </form>

            <?php if ($output !== null): ?>
            <div style="margin-top:1rem;">
                <label style="font-size:0.82rem; color:var(--text-muted);">Output (may be base64-encoded):</label>
                <div class="output-box <?= empty(trim($output)) ? 'empty' : '' ?>"><?= htmlspecialchars($output) ?></div>
            </div>
            <?php if ($rawOutput !== '' && $rawOutput !== $output): ?>
            <div style="margin-top:0.5rem;">
                <label style="font-size:0.82rem; color:var(--text-muted);">Base64 decoded:</label>
                <div class="output-box"><?= htmlspecialchars(@base64_decode($rawOutput) ?: '') ?></div>
            </div>
            <?php endif; ?>
            <?php endif; ?>

            <?php if ($flagFound): ?>
            <div class="message success">Flag captured! A FLAG{} string was detected (raw or after base64 decode).</div>
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
        <span style="color:var(--text-muted); font-size:0.85rem;">Level 3 / 10</span>
        <a href="level2.php" class="prev-link">&larr; Previous</a>
        <a href="index.php" class="nav-link">Home</a>
        <a href="level4.php" class="next-link">Next Level &rarr;</a>
        <a href="submit.php" class="nav-link">Submit Flag</a>
    </div>
</div>
</body>
</html>
