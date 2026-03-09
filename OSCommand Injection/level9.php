<?php
require_once __DIR__ . '/helpers.php';

$output_html = '';

if (isset($_GET['pattern'])) {
    require_once 'flag_system.php';
    get_level_flag(9);

    $pattern = $_GET['pattern'];

    // Execute command — output completely suppressed
    $command = "netstat -an | grep " . $pattern . " > /dev/null 2>&1";
    $result  = shell_exec($command);

    // Always show same generic response regardless of input
    $output_html = '<div class="message success">Network monitoring completed</div>'
                 . '<div class="message success">Results logged to internal system</div>'
                 . '<div class="message success">No direct output available for security reasons</div>';
}

$hints = get_level_hints(9);
$_flag_result = handle_inline_flag_submit(9);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 9 - Out-of-Band Injection</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 9 - Out-of-Band Injection</h1>
            <p><strong>Objective:</strong> Use out-of-band techniques to exfiltrate data through the network</p>
            <a href="index.php" class="back-btn">&larr; Back to Levels</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-variable">$pattern</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'pattern'</span>];

<span class="php-comment">// No filtering — output completely discarded</span>
<span class="vuln-line"><span class="php-variable">$command</span> = <span class="php-string">"netstat -an | grep "</span> . <span class="php-variable">$pattern</span>
         . <span class="php-string">" &gt; /dev/null 2&gt;&amp;1"</span>;</span>
<span class="php-variable">$result</span>  = shell_exec(<span class="php-variable">$command</span>);

<span class="php-comment">// Always return the same generic response</span>
<span class="php-keyword">echo</span> <span class="php-string">'Network monitoring completed'</span>;</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$pattern</code> is concatenated into the command with no filtering. All output is discarded with <code>&gt; /dev/null 2&gt;&amp;1</code> and the page always returns a fixed response — making in-band extraction impossible. Data must leave the server through an out-of-band channel (DNS, HTTP callback, or Docker file copy).
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <p><strong>Tool:</strong> Network Monitor — runs <code>netstat -an | grep &lt;input&gt; &gt; /dev/null 2&gt;&amp;1</code>. Output is completely suppressed and the page always returns the same fixed message regardless of what executes.</p>
                        <p>There is no in-band feedback at all. Exfiltrate the flag via DNS lookups, HTTP callbacks to a listener you control, or by copying the flag to a web-accessible path inside the container.</p>
                    </div>

                    <?php if ($output_html !== ''): ?>
                        <div class="result"><?= $output_html ?></div>
                    <?php endif; ?>

                    <form method="get">
                        <div class="form-group">
                            <label for="pattern">Search Pattern:</label>
                            <input type="text" id="pattern" name="pattern"
                                   value="<?= htmlspecialchars($_GET['pattern'] ?? '') ?>"
                                   placeholder="e.g., :80">
                        </div>
                        <button type="submit" class="btn">Monitor Network</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section($hints) ?>

        <?= render_inline_flag_form(9, $_flag_result) ?>

        <div class="navigation">
            <a href="level8.php">Previous Level</a>
            <a href="index.php">Home</a>
            <a href="level10.php">Next Level</a>
            <a href="submit.php?level=9">Submit Flag</a>
        </div>
    </div>
</body>
</html>
