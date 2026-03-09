<?php
require_once __DIR__ . '/helpers.php';

$output_html = '';

if (isset($_GET['logfile'])) {
    require_once 'flag_system.php';
    get_level_flag(7);

    $logfile       = $_GET['logfile'];
    $blocked_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', ' ', 'cat', 'ls', 'whoami', 'id'];
    $is_blocked    = false;

    foreach ($blocked_chars as $char) {
        if (strpos($logfile, $char) !== false) {
            $is_blocked  = true;
            $output_html = '<div class="error">Blocked character detected: ' . htmlspecialchars($char) . '</div>';
            break;
        }
    }

    if (!$is_blocked) {
        $command = "tail -n 10 /var/log/" . $logfile . ".log | grep 'ERROR'";
        $raw     = shell_exec($command . " 2>&1");

        ob_start();
        if ($raw) {
            echo '<pre>' . htmlspecialchars($raw) . '</pre>';
        } else {
            echo '<div class="message success">No errors found in log file</div>';
        }
        $output_html = ob_get_clean();
    }
}

$hints = get_level_hints(7);
$_flag_result = handle_inline_flag_submit(7);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 7 - Output Redirection &amp; Encoding</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 7 - Output Redirection &amp; Encoding</h1>
            <p><strong>Objective:</strong> Use encoding and path traversal to bypass advanced character filters</p>
            <a href="index.php" class="back-btn">&larr; Back to Levels</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-variable">$logfile</span>       = <span class="php-variable">$_GET</span>[<span class="php-string">'logfile'</span>];
<span class="php-variable">$blocked_chars</span> = [<span class="php-string">';'</span>, <span class="php-string">'&amp;'</span>, <span class="php-string">'|'</span>, <span class="php-string">'`'</span>, <span class="php-string">'$'</span>,
                  <span class="php-string">'('</span>, <span class="php-string">')'</span>, <span class="php-string">'&lt;'</span>, <span class="php-string">'&gt;'</span>, <span class="php-string">' '</span>,
                  <span class="php-string">'cat'</span>, <span class="php-string">'ls'</span>, <span class="php-string">'whoami'</span>, <span class="php-string">'id'</span>];

<span class="php-keyword">foreach</span> (<span class="php-variable">$blocked_chars</span> <span class="php-keyword">as</span> <span class="php-variable">$char</span>) {
    <span class="php-keyword">if</span> (strpos(<span class="php-variable">$logfile</span>, <span class="php-variable">$char</span>) !== <span class="php-keyword">false</span>) {
        <span class="php-keyword">echo</span> <span class="php-string">'Blocked: '</span> . <span class="php-variable">$char</span>; <span class="php-keyword">exit</span>;
    }
}

<span class="php-comment">// ../ is NOT in the blocked list — path traversal possible</span>
<span class="vuln-line"><span class="php-variable">$command</span> = <span class="php-string">"tail -n 10 /var/log/"</span> . <span class="php-variable">$logfile</span> . <span class="php-string">".log | grep 'ERROR'"</span>;</span>
<span class="php-variable">$output</span>  = shell_exec(<span class="php-variable">$command</span> . <span class="php-string">" 2&gt;&amp;1"</span>);</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; Many shell metacharacters are blocked, but <code>../</code> and the newline byte (<code>%0a</code>) are not filtered. Path traversal escapes <code>/var/log/</code>; newline injection lets you append a second shell command before the static <code>.log</code> suffix is processed.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <p><strong>Tool:</strong> Log Analyzer — runs <code>tail -n 10 /var/log/&lt;input&gt;.log | grep 'ERROR'</code>. Blocks <code>; &amp; | ` $ () &lt;&gt; space cat ls whoami id</code>, but <code>../</code> and newline are left open.</p>
                        <p>Use path traversal and/or newline injection to read arbitrary files or run alternative read commands like <code>od</code>, <code>xxd</code>, or <code>tac</code>.</p>
                    </div>

                    <?php if ($output_html !== ''): ?>
                        <div class="result"><?= $output_html ?></div>
                    <?php endif; ?>

                    <form method="get">
                        <div class="form-group">
                            <label for="logfile">Log File Name:</label>
                            <input type="text" id="logfile" name="logfile"
                                   value="<?= htmlspecialchars($_GET['logfile'] ?? '') ?>"
                                   placeholder="e.g., apache">
                        </div>
                        <button type="submit" class="btn">Analyze Log</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section($hints) ?>

        <?= render_inline_flag_form(7, $_flag_result) ?>

        <div class="navigation">
            <a href="level6.php">Previous Level</a>
            <a href="index.php">Home</a>
            <a href="level8.php">Next Level</a>
            <a href="submit.php?level=7">Submit Flag</a>
        </div>
    </div>
</body>
</html>
