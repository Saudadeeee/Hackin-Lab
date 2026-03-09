<?php
require_once __DIR__ . '/helpers.php';

$result_output   = null;
$result_error    = null;

if (isset($_GET['process'])) {
    require_once 'flag_system.php';
    get_level_flag(4);

    $process = $_GET['process'];

    // Security filters — block dangerous keywords (case-insensitive)
    $blocked_keywords = ['cat', 'less', 'more', 'head', 'tail', 'flag', 'passwd', 'shadow'];
    $is_blocked = false;

    foreach ($blocked_keywords as $keyword) {
        if (stripos($process, $keyword) !== false) {
            $is_blocked   = true;
            $result_error = 'Security Alert: Keyword "' . $keyword . '" is blocked!';
            break;
        }
    }

    if (!$is_blocked) {
        $command = "ps aux | grep " . $process;
        $output  = shell_exec($command);

        if ($output) {
            $result_output = $output;
        } else {
            $result_error = 'No output or command failed';
        }
    }
}

$hints = get_level_hints(4);
$_flag_result = handle_inline_flag_submit(4);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 4 - Keyword Filter Bypass</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 4 - Keyword Filter Bypass</h1>
            <p><strong>Objective:</strong> Bypass keyword filtering to perform command injection.</p>
            <a href="index.php" class="back-btn">&larr; Back to Levels</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-variable">$process</span>  = <span class="php-variable">$_GET</span>[<span class="php-string">'process'</span>];
<span class="php-variable">$blocked</span>  = [<span class="php-string">'cat'</span>, <span class="php-string">'less'</span>, <span class="php-string">'more'</span>, <span class="php-string">'head'</span>, <span class="php-string">'tail'</span>,
              <span class="php-string">'flag'</span>, <span class="php-string">'passwd'</span>, <span class="php-string">'shadow'</span>];

<span class="php-comment">// Case-insensitive substring match — no anchoring</span>
<span class="php-keyword">foreach</span> (<span class="php-variable">$blocked</span> <span class="php-keyword">as</span> <span class="php-variable">$kw</span>) {
    <span class="php-keyword">if</span> (<span class="php-function">stripos</span>(<span class="php-variable">$process</span>, <span class="php-variable">$kw</span>) !== <span class="php-keyword">false</span>) {
        <span class="php-keyword">echo</span> <span class="php-string">'Blocked: '</span> . <span class="php-variable">$kw</span>;
        <span class="php-keyword">exit</span>;
    }
}

<span class="vuln-line"><span class="php-variable">$command</span> = <span class="php-string">"ps aux | grep "</span> . <span class="php-variable">$process</span>;</span>
<span class="php-variable">$output</span>  = <span class="php-function">shell_exec</span>(<span class="php-variable">$command</span>);
<span class="php-keyword">echo</span> <span class="php-function">htmlspecialchars</span>(<span class="php-variable">$output</span>);</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>stripos</code> checks for a plain substring. Breaking the keyword with empty quotes (<code>c''at</code>), variable assembly (<code>$a$b</code>), or filesystem globs (<code>/bin/c?t</code>) satisfies the shell without triggering the string match.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <p><strong>Scenario:</strong> A process monitor pipes <code>ps aux</code> into <code>grep</code> with your input. Keywords <code>cat</code>, <code>less</code>, <code>more</code>, <code>head</code>, <code>tail</code>, <code>flag</code>, <code>passwd</code>, and <code>shadow</code> are blocked by case-insensitive substring matching. Bypass the filter with quote-splitting, variable assembly, or wildcards to read the flag.</p>
                    </div>

                    <div class="code-block">Command: ps aux | grep <?php echo htmlspecialchars($_GET['process'] ?? '[PROCESS]'); ?></div>

                    <?php if ($result_error !== null): ?>
                        <div class="error"><?php echo htmlspecialchars($result_error); ?></div>
                    <?php endif; ?>
                    <?php if ($result_output !== null): ?>
                        <div class="result"><pre><?php echo htmlspecialchars($result_output); ?></pre></div>
                    <?php endif; ?>

                    <form method="get">
                        <div class="form-group">
                            <label for="process">Process Name:</label>
                            <input type="text" id="process" name="process"
                                   value="<?php echo htmlspecialchars($_GET['process'] ?? ''); ?>"
                                   placeholder="Enter process name (e.g., apache)"
                                   oninput="updateCommand(this.value)">
                        </div>
                        <button type="submit" class="btn">Search Process</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section($hints) ?>

        <?= render_inline_flag_form(4, $_flag_result) ?>

        <div class="navigation">
            <a href="level3.php">Previous Level</a>
            <a href="index.php">Home</a>
            <a href="level5.php">Next Level</a>
            <a href="submit.php?level=4">Submit Flag</a>
        </div>
    </div>

    <script>
    function updateCommand(val) {
        document.querySelector('.code-block').textContent =
            'Command: ps aux | grep ' + (val || '[PROCESS]');
    }
    </script>
</body>
</html>
