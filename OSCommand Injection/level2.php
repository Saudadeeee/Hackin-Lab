<?php
require_once __DIR__ . '/helpers.php';

$result_output = null;
$result_error  = null;

if (isset($_GET['service'])) {
    require_once 'flag_system.php';
    get_level_flag(2);

    $service = $_GET['service'];

    // Basic security filter — block semicolon only
    if (strpos($service, ';') !== false) {
        $result_error = 'Security Alert: Semicolon (;) is not allowed!';
    } else {
        $command = "systemctl status " . $service . " 2>/dev/null || echo 'Service not found'";
        $output  = shell_exec($command);

        if ($output) {
            $result_output = $output;
        } else {
            $result_error = 'No output or command failed';
        }
    }
}

$hints = get_level_hints(2);
$_flag_result = handle_inline_flag_submit(2);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 2 - Basic Filter Bypass</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 2 - Basic Filter Bypass</h1>
            <p><strong>Objective:</strong> Bypass basic character filtering to perform command injection.</p>
            <a href="index.php" class="back-btn">&larr; Back to Levels</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-variable">$service</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'service'</span>];

<span class="php-comment">// Only blocks semicolon — &&, ||, | pass freely</span>
<span class="php-keyword">if</span> (<span class="php-function">strpos</span>(<span class="php-variable">$service</span>, <span class="php-string">';'</span>) !== <span class="php-keyword">false</span>) {
    <span class="php-keyword">echo</span> <span class="php-string">'Security Alert: Semicolon blocked!'</span>;
} <span class="php-keyword">else</span> {
<span class="vuln-line">    <span class="php-variable">$command</span> = <span class="php-string">"systemctl status "</span> . <span class="php-variable">$service</span> . <span class="php-string">" 2&gt;/dev/null || echo 'not found'"</span>;</span>
    <span class="php-variable">$output</span> = <span class="php-function">shell_exec</span>(<span class="php-variable">$command</span>);
    <span class="php-keyword">echo</span> <span class="php-function">htmlspecialchars</span>(<span class="php-variable">$output</span>);
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; The filter only blocks <code>;</code>. Operators <code>&amp;&amp;</code>, <code>||</code>, and <code>|</code> are not filtered, so <code>$service</code> can still chain arbitrary commands into the shell.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <p><strong>Scenario:</strong> A service status checker passes your input to <code>systemctl status</code>. Semicolons are blocked, but other shell operators are not. Use <code>&amp;&amp;</code>, <code>||</code>, or <code>|</code> to chain a second command and read the flag.</p>
                    </div>

                    <div class="code-block">Command: systemctl status <?php echo htmlspecialchars($_GET['service'] ?? '[SERVICE]'); ?></div>

                    <?php if ($result_error !== null): ?>
                        <div class="error"><?php echo htmlspecialchars($result_error); ?></div>
                    <?php endif; ?>
                    <?php if ($result_output !== null): ?>
                        <div class="result"><pre><?php echo htmlspecialchars($result_output); ?></pre></div>
                    <?php endif; ?>

                    <form method="get">
                        <div class="form-group">
                            <label for="service">Service Name:</label>
                            <input type="text" id="service" name="service"
                                   value="<?php echo htmlspecialchars($_GET['service'] ?? ''); ?>"
                                   placeholder="Enter service name (e.g., apache2)"
                                   oninput="updateCommand(this.value)">
                        </div>
                        <button type="submit" class="btn">Check Service</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section($hints) ?>

        <?= render_inline_flag_form(2, $_flag_result) ?>

        <div class="navigation">
            <a href="level1.php">Previous Level</a>
            <a href="index.php">Home</a>
            <a href="level3.php">Next Level</a>
            <a href="submit.php?level=2">Submit Flag</a>
        </div>
    </div>

    <script>
    function updateCommand(val) {
        document.querySelector('.code-block').textContent =
            'Command: systemctl status ' + (val || '[SERVICE]');
    }
    </script>
</body>
</html>
