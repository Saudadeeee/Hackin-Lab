<?php
require_once __DIR__ . '/helpers.php';

$levelNum  = 7;
$_flag_result = handle_inline_flag_submit($levelNum);
$output    = null;
$flagFound = false;
$flagValue = '';

if (isset($_GET['resource'])) {
    $resource = $_GET['resource'];
    // --- VULNERABLE CODE (same as shown in source panel) ---
    if (strpos($resource, '..') !== false) {
        $output = '[Path traversal detected!]';
    } else {
        $content = @file_get_contents($resource);
        if ($content === false) {
            $output = '[Error: Could not read resource]';
        } else {
            // htmlspecialchars doesn't stop base64 output
            $output = htmlspecialchars($content);
            // Check raw and base64-decoded for flag
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
    <title>Level 7 - PHP Wrapper + htmlspecialchars | Path Traversal Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
<div class="header">
    <div>
        <h1>Level 7 &mdash; Bypass htmlspecialchars with PHP Wrapper</h1>
        <p>Hard &bull; Output is HTML-encoded — use a wrapper that produces base64</p>
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
<span class="php-variable">$resource</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'resource'</span>] ?? <span class="php-string">'files/welcome.txt'</span>;
<span class="php-keyword">if</span> (<span class="php-function">strpos</span>(<span class="php-variable">$resource</span>, <span class="php-string">'..'</span>) !== <span class="php-keyword">false</span>) {
    <span class="php-function">die</span>(<span class="php-string">"Path traversal detected!"</span>);
}
<span class="vuln-line"><span class="php-variable">$content</span> = <span class="php-function">file_get_contents</span>(<span class="php-variable">$resource</span>);        <span class="php-comment">// supports PHP wrappers</span></span>
<span class="php-function">echo</span> <span class="php-function">htmlspecialchars</span>(<span class="php-variable">$content</span>);                 <span class="php-comment">// VULN: htmlspecialchars doesn't stop base64</span>
<span class="php-keyword">?&gt;</span></code>
            </div>
            <div style="margin-top:1rem; font-size:0.85rem; color:var(--text-muted); line-height:1.7;">
                <strong style="color:var(--text);">What to look for:</strong><br>
                <code>htmlspecialchars()</code> encodes <code>&lt; &gt; &amp; ' &quot;</code> —
                characters common in HTML/PHP source. But base64-encoded content consists
                only of <code>[A-Za-z0-9+/=]</code> — none of those are affected.<br><br>
                The <code>..</code> block prevents traversal, but
                <code>php://filter/convert.base64-encode/resource=</code> uses an absolute
                path and returns base64. The <code>htmlspecialchars</code> leaves base64 intact.<br><br>
                <strong style="color:var(--text);">Goal:</strong>
                Read <code>/var/secret/level7_flag.txt</code> via <code>php://filter</code>,
                then base64-decode the result.
            </div>
        </div>

        <!-- RIGHT: Challenge Panel -->
        <div class="challenge-panel">
            <h3>Challenge</h3>
            <div class="scenario">
                <strong>Scenario:</strong> Two defences are in place: <code>..</code> is blocked and
                output passes through <code>htmlspecialchars()</code>. The PHP filter wrapper
                bypasses both — it uses an absolute path (no <code>..</code>) and returns
                base64 that survives HTML encoding unchanged.
            </div>

            <form method="GET" action="level7.php">
                <div class="form-group">
                    <label for="resource">Resource parameter (<code>?resource=</code>)</label>
                    <input type="text" id="resource" name="resource" class="form-control"
                           placeholder="e.g. php://filter/convert.base64-encode/resource=..."
                           value="<?= htmlspecialchars($_GET['resource'] ?? '') ?>">
                </div>
                <button type="submit" class="btn btn-primary">Read Resource</button>
            </form>

            <?php if ($output !== null): ?>
            <div style="margin-top:1rem;">
                <label style="font-size:0.82rem; color:var(--text-muted);">Output (base64-encoded if using php://filter):</label>
                <div class="output-box <?= empty(trim($output)) ? 'empty' : '' ?>"><?= $output /* already htmlspecialchars'd */ ?></div>
            </div>
            <?php
            // Show decoded output if it looks like base64
            $rawForDecode = $_GET['resource'] ?? '';
            if (strpos($rawForDecode, 'base64') !== false && isset($content) && $content !== false) {
                $decoded = @base64_decode($content, true);
                if ($decoded !== false) { ?>
            <div style="margin-top:0.5rem;">
                <label style="font-size:0.82rem; color:var(--text-muted);">Base64 decoded:</label>
                <div class="output-box"><?= htmlspecialchars($decoded) ?></div>
            </div>
            <?php } } ?>
            <?php endif; ?>

            <?php if ($flagFound): ?>
            <div class="message success">Flag captured! Detected in output (raw or decoded).</div>
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
        <span style="color:var(--text-muted); font-size:0.85rem;">Level 7 / 10</span>
        <a href="level6.php" class="prev-link">&larr; Previous</a>
        <a href="index.php" class="nav-link">Home</a>
        <a href="level8.php" class="next-link">Next Level &rarr;</a>
        <a href="submit.php" class="nav-link">Submit Flag</a>
    </div>
</div>
</body>
</html>
