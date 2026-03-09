<?php
require_once __DIR__ . '/helpers.php';

session_start();

$output_html = '';

if (isset($_GET['process'])) {
    require_once 'flag_system.php';
    get_level_flag(10);

    $process      = $_GET['process'];
    $current_time = time();

    // Rate limiting — 1 request per 2 seconds per session
    if (isset($_SESSION['last_request']) &&
        ($current_time - $_SESSION['last_request']) < 2) {

        $wait_time   = 2 - ($current_time - $_SESSION['last_request']);
        $output_html = '<div class="error">Rate limit exceeded. Please wait ' . $wait_time . ' second(s).</div>'
                     . '<div class="error">Request blocked by rate limiter</div>';
    } else {
        $_SESSION['last_request'] = $current_time;

        // No command filtering at all
        $command = "timeout 1s ps aux | grep " . $process;
        $raw     = shell_exec($command . " 2>&1");

        ob_start();
        if ($raw) {
            echo '<pre>' . htmlspecialchars($raw) . '</pre>';
        } else {
            echo '<div class="message success">No matching processes found</div>';
        }
        $output_html = ob_get_clean();
    }
}

$hints = get_level_hints(10);
$_flag_result = handle_inline_flag_submit(10);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 10 - Race Condition &amp; Automation</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 10 - Race Condition &amp; Automation</h1>
            <p><strong>Objective:</strong> Bypass session-based rate limiting and exploit an unfiltered command injection</p>
            <a href="index.php" class="back-btn">&larr; Back to Levels</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code>session_start();

<span class="php-variable">$process</span>      = <span class="php-variable">$_GET</span>[<span class="php-string">'process'</span>];
<span class="php-variable">$current_time</span> = time();

<span class="php-comment">// Rate limit: 1 request per 2 seconds via session</span>
<span class="php-keyword">if</span> (<span class="php-keyword">isset</span>(<span class="php-variable">$_SESSION</span>[<span class="php-string">'last_request'</span>]) &amp;&amp;
    (<span class="php-variable">$current_time</span> - <span class="php-variable">$_SESSION</span>[<span class="php-string">'last_request'</span>]) &lt; 2) {
    <span class="php-keyword">echo</span> <span class="php-string">'Rate limit exceeded'</span>; <span class="php-keyword">exit</span>;
}

<span class="php-variable">$_SESSION</span>[<span class="php-string">'last_request'</span>] = <span class="php-variable">$current_time</span>;

<span class="php-comment">// No filtering whatsoever</span>
<span class="vuln-line"><span class="php-variable">$command</span> = <span class="php-string">"timeout 1s ps aux | grep "</span> . <span class="php-variable">$process</span>;</span>
<span class="php-variable">$output</span>  = shell_exec(<span class="php-variable">$command</span> . <span class="php-string">" 2&gt;&amp;1"</span>);</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$process</code> is concatenated directly into the command with absolutely no filtering. The only defence is a session-based rate limiter (1 req/2 s). Bypass the rate limit by sending a fresh session cookie or clearing <code>$_SESSION['last_request']</code>, then read the flag from <code>/tmp/level10_flag.txt</code>.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <p><strong>Tool:</strong> Batch Process Manager — runs <code>timeout 1s ps aux | grep &lt;input&gt;</code>. No command filtering at all. Output is shown directly, so this is not blind injection.</p>
                        <p>The only obstacle is the 2-second session rate limit. Clear your session cookie, use a fresh incognito tab, or send concurrent requests to bypass it, then inject directly to read the flag.</p>
                    </div>

                    <?php if ($output_html !== ''): ?>
                        <div class="result"><?= $output_html ?></div>
                    <?php endif; ?>

                    <form method="get">
                        <div class="form-group">
                            <label for="process">Process Name:</label>
                            <input type="text" id="process" name="process"
                                   value="<?= htmlspecialchars($_GET['process'] ?? '') ?>"
                                   placeholder="e.g., apache">
                        </div>
                        <button type="submit" class="btn">Search Process</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section($hints) ?>

        <?= render_inline_flag_form(10, $_flag_result) ?>

        <div class="navigation">
            <a href="level9.php">Previous Level</a>
            <a href="index.php">Home</a>
            <a href="submit.php?level=10">Submit Flag</a>
        </div>
    </div>
</body>
</html>
