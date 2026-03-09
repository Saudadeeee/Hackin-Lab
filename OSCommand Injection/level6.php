<?php
require_once __DIR__ . '/helpers.php';

$output_html = '';

if (isset($_GET['service'])) {
    require_once 'flag_system.php';
    get_level_flag(6);

    $start_time = microtime(true);
    $service    = $_GET['service'];

    $command = "systemctl is-active " . $service . " && echo 'Service OK' || echo 'Service Failed'";
    $result  = shell_exec($command . " 2>/dev/null");

    $end_time       = microtime(true);
    $execution_time = round(($end_time - $start_time), 2);

    ob_start();
    echo '<div class="message success">Health check completed</div>';
    echo '<p><strong>Execution time:</strong> ' . $execution_time . ' seconds</p>';
    echo '<p><strong>Status:</strong> Logged to system audit</p>';
    $output_html = ob_get_clean();
}

$hints = get_level_hints(6);
$_flag_result = handle_inline_flag_submit(6);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 6 - Time-based Detection</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 6 - Time-based Detection</h1>
            <p><strong>Objective:</strong> Use time-based techniques to detect and exploit blind injection</p>
            <a href="index.php" class="back-btn">&larr; Back to Levels</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-variable">$service</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'service'</span>];

<span class="php-comment">// Execute command — output hidden, time revealed</span>
<span class="vuln-line"><span class="php-variable">$command</span> = <span class="php-string">"systemctl is-active "</span> . <span class="php-variable">$service</span>
         . <span class="php-string">" &amp;&amp; echo 'Service OK' || echo 'Service Failed'"</span>;</span>
<span class="php-variable">$result</span> = shell_exec(<span class="php-variable">$command</span> . <span class="php-string">" 2&gt;/dev/null"</span>);

<span class="php-variable">$end_time</span>       = microtime(<span class="php-keyword">true</span>);
<span class="php-variable">$execution_time</span> = round(<span class="php-variable">$end_time</span> - <span class="php-variable">$start_time</span>, 2);

<span class="php-comment">// Only execution time is exposed — output is suppressed</span>
<span class="php-keyword">echo</span> <span class="php-string">"Execution time: {$execution_time}s"</span>;</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$service</code> from <code>$_GET['service']</code> is concatenated directly into the shell command without any sanitization. Output is suppressed, but execution time is reported — a timing oracle confirming whether injected payloads (e.g. <code>sleep N</code>) ran.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <p><strong>Tool:</strong> System Health Checker — verifies service status via <code>systemctl is-active</code>. Real command output is suppressed; only execution time is shown.</p>
                        <p>Inject a <code>sleep</code> command and observe the reported seconds to confirm blind execution, then exfiltrate the flag from <code>/tmp/level6_flag.txt</code>.</p>
                    </div>

                    <?php if ($output_html !== ''): ?>
                        <div class="result"><?= $output_html ?></div>
                    <?php endif; ?>

                    <form method="get">
                        <div class="form-group">
                            <label for="service">Service Name:</label>
                            <input type="text" id="service" name="service"
                                   value="<?= htmlspecialchars($_GET['service'] ?? '') ?>"
                                   placeholder="e.g., apache2">
                        </div>
                        <button type="submit" class="btn">Check Service</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section($hints) ?>

        <?= render_inline_flag_form(6, $_flag_result) ?>

        <div class="navigation">
            <a href="level5.php">Previous Level</a>
            <a href="index.php">Home</a>
            <a href="level7.php">Next Level</a>
            <a href="submit.php?level=6">Submit Flag</a>
        </div>
    </div>
</body>
</html>
