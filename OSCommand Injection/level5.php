<?php
require_once __DIR__ . '/helpers.php';

$result_message = null;
$result_success = false;

if (isset($_GET['email'])) {
    // Initialize level-specific flag access
    require_once 'flag_system.php';
    get_level_flag(5);

    $email   = $_GET['email'];

    // Extract domain and ping it (blind — output is completely hidden)
    $command = "ping -c 1 $(echo " . $email . " | cut -d@ -f2) > /dev/null 2>&1";

    // Execute command but suppress all output for "security"
    shell_exec($command);
    $exit_code = shell_exec("echo $?");

    // Only reveal generic success or failure
    if (trim($exit_code) == "0") {
        $result_message = 'Email domain is reachable';
        $result_success = true;
    } else {
        $result_message = 'Email domain is not reachable';
    }
}

$hints = get_level_hints(5);
$_flag_result = handle_inline_flag_submit(5);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 5 - Blind Command Injection</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 5 - Blind Command Injection</h1>
            <p><strong>Objective:</strong> Exploit command injection when no direct output is returned.</p>
            <a href="index.php" class="back-btn">&larr; Back to Levels</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-variable">$email</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'email'</span>];

<span class="php-comment">// Input embedded inside command substitution — no filter</span>
<span class="vuln-line"><span class="php-variable">$command</span> = <span class="php-string">"ping -c 1 $(echo "</span> . <span class="php-variable">$email</span> . <span class="php-string">" | cut -d@ -f2) &gt; /dev/null 2&gt;&amp;1"</span>;</span>

<span class="php-comment">// All output is silenced — completely blind</span>
<span class="php-function">shell_exec</span>(<span class="php-variable">$command</span>);
<span class="php-variable">$code</span> = <span class="php-function">shell_exec</span>(<span class="php-string">"echo $?"</span>);

<span class="php-comment">// Only a pass / fail status is revealed</span>
<span class="php-keyword">if</span> (<span class="php-function">trim</span>(<span class="php-variable">$code</span>) == <span class="php-string">"0"</span>) {
    <span class="php-keyword">echo</span> <span class="php-string">'Email domain is reachable'</span>;
} <span class="php-keyword">else</span> {
    <span class="php-keyword">echo</span> <span class="php-string">'Email domain is not reachable'</span>;
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$email</code> is injected unsanitized inside <code>$(echo … | cut -d@ -f2)</code>. All output is redirected to <code>/dev/null</code>, making this a blind injection — detect and exfiltrate via time delays, file writes, or out-of-band channels.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <p><strong>Scenario:</strong> An email validator pings the domain extracted from your address. Your input lands inside a command substitution with no filtering, but <strong>all output is silenced</strong> — you only see reachable / not reachable. Prove injection with a time delay, then exfiltrate the flag by writing it to a web-accessible path.</p>
                    </div>

                    <div class="code-block">Command: ping -c 1 $(echo <?php echo htmlspecialchars($_GET['email'] ?? '[EMAIL]'); ?> | cut -d@ -f2) &gt; /dev/null 2&gt;&amp;1</div>

                    <?php if ($result_message !== null): ?>
                        <?php if ($result_success): ?>
                            <div class="message success"><?php echo htmlspecialchars($result_message); ?></div>
                        <?php else: ?>
                            <div class="error"><?php echo htmlspecialchars($result_message); ?></div>
                        <?php endif; ?>
                    <?php endif; ?>

                    <form method="get">
                        <div class="form-group">
                            <label for="email">Email Address:</label>
                            <input type="text" id="email" name="email"
                                   value="<?php echo htmlspecialchars($_GET['email'] ?? ''); ?>"
                                   placeholder="Enter email (e.g., user@google.com)"
                                   oninput="updateCommand(this.value)">
                        </div>
                        <button type="submit" class="btn">Validate Email</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section($hints) ?>

        <?= render_inline_flag_form(5, $_flag_result) ?>

        <div class="navigation">
            <a href="level4.php">Previous Level</a>
            <a href="index.php">Home</a>
            <a href="level6.php">Next Level</a>
            <a href="submit.php?level=5">Submit Flag</a>
        </div>
    </div>

    <script>
    function updateCommand(val) {
        document.querySelector('.code-block').textContent =
            'Command: ping -c 1 $(echo ' + (val || '[EMAIL]') + ' | cut -d@ -f2) > /dev/null 2>&1';
    }
    </script>
</body>
</html>
