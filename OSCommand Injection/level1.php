<?php
require_once __DIR__ . '/helpers.php';

$result_output = null;
$result_error  = null;

if (isset($_GET['ip'])) {
    // Initialize level-specific flag access
    require_once 'flag_system.php';
    get_level_flag(1);

    $ip      = $_GET['ip'];
    $command = "ping -c 4 " . $ip;
    $output  = shell_exec($command);

    if ($output) {
        $result_output = $output;
    } else {
        $result_error = 'No output or command failed';
    }
}

$hints = get_level_hints(1);
$_flag_result = handle_inline_flag_submit(1);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 1 - Basic OS Command Injection</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 1 - Basic Command Injection</h1>
            <p><strong>Objective:</strong> Perform basic OS Command Injection to retrieve system information.</p>
            <a href="index.php" class="back-btn">&larr; Back to Levels</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-keyword">if</span> (<span class="php-function">isset</span>(<span class="php-variable">$_GET</span>[<span class="php-string">'ip'</span>])) {

    <span class="php-variable">$ip</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'ip'</span>];

    <span class="php-comment">// Vulnerable — no sanitization whatsoever</span>
<span class="vuln-line">    <span class="php-variable">$command</span> = <span class="php-string">"ping -c 4 "</span> . <span class="php-variable">$ip</span>;</span>
    <span class="php-variable">$output</span>  = <span class="php-function">shell_exec</span>(<span class="php-variable">$command</span>);

    <span class="php-keyword">if</span> (<span class="php-variable">$output</span>) {
        <span class="php-keyword">echo</span> <span class="php-string">'&lt;pre&gt;'</span> . <span class="php-function">htmlspecialchars</span>(<span class="php-variable">$output</span>) . <span class="php-string">'&lt;/pre&gt;'</span>;
    } <span class="php-keyword">else</span> {
        <span class="php-keyword">echo</span> <span class="php-string">'No output or command failed'</span>;
    }
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$_GET['ip']</code> is concatenated directly into the shell command string with no sanitization. Any shell metacharacter you inject becomes part of the OS command.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <p><strong>Scenario:</strong> A network tool pings the IP address you supply. The raw input is appended to <code>ping -c 4</code> with no checks whatsoever. Inject a second command after the IP to read the flag.</p>
                    </div>

                    <div class="code-block">Command: ping -c 4 <?php echo htmlspecialchars($_GET['ip'] ?? '[IP_ADDRESS]'); ?></div>

                    <?php if ($result_output !== null): ?>
                        <div class="result"><pre><?php echo htmlspecialchars($result_output); ?></pre></div>
                    <?php elseif ($result_error !== null): ?>
                        <div class="result"><?php echo htmlspecialchars($result_error); ?></div>
                    <?php endif; ?>

                    <form method="get">
                        <div class="form-group">
                            <label for="ip">IP Address:</label>
                            <input type="text" id="ip" name="ip"
                                   value="<?php echo htmlspecialchars($_GET['ip'] ?? ''); ?>"
                                   placeholder="Enter IP address (e.g., 8.8.8.8)"
                                   oninput="updateCommand(this.value)">
                        </div>
                        <button type="submit" class="btn">Execute Ping</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section($hints) ?>

        <?= render_inline_flag_form(1, $_flag_result) ?>

        <div class="navigation">
            <a href="index.php">Home</a>
            <a href="level2.php">Next Level</a>
            <a href="submit.php?level=1">Submit Flag</a>
        </div>
    </div>

    <script>
    function updateCommand(val) {
        document.querySelector('.code-block').textContent =
            'Command: ping -c 4 ' + (val || '[IP_ADDRESS]');
    }
    </script>
</body>
</html>
