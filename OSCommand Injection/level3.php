<?php
require_once __DIR__ . '/helpers.php';

$result_output = null;
$result_error  = null;

if (isset($_GET['filename'])) {
    require_once 'flag_system.php';
    get_level_flag(3);

    $filename = $_GET['filename'];

    // Security filter — block literal space character only
    if (strpos($filename, ' ') !== false) {
        $result_error = 'Security Alert: Spaces are not allowed!';
    } else {
        $command = "file " . $filename;
        $output  = shell_exec($command);

        if ($output) {
            $result_output = $output;
        } else {
            $result_error = 'No output or command failed';
        }
    }
}

$hints = get_level_hints(3);
$_flag_result = handle_inline_flag_submit(3);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 3 - Space Filter Bypass</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 3 - Space Filter Bypass</h1>
            <p><strong>Objective:</strong> Bypass space character filtering to perform command injection.</p>
            <a href="index.php" class="back-btn">&larr; Back to Levels</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-variable">$filename</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'filename'</span>];

<span class="php-comment">// Only blocks the literal space character (0x20)</span>
<span class="php-keyword">if</span> (<span class="php-function">strpos</span>(<span class="php-variable">$filename</span>, <span class="php-string">' '</span>) !== <span class="php-keyword">false</span>) {
    <span class="php-keyword">echo</span> <span class="php-string">'Security Alert: Spaces are not allowed!'</span>;
} <span class="php-keyword">else</span> {
<span class="vuln-line">    <span class="php-variable">$command</span> = <span class="php-string">"file "</span> . <span class="php-variable">$filename</span>;</span>
    <span class="php-variable">$output</span>  = <span class="php-function">shell_exec</span>(<span class="php-variable">$command</span>);
    <span class="php-keyword">echo</span> <span class="php-function">htmlspecialchars</span>(<span class="php-variable">$output</span>);
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; Only the ASCII space (0x20) is blocked. <code>$filename</code> is still concatenated unsanitized. Use <code>${IFS}</code>, a URL-encoded tab <code>%09</code>, or brace expansion to separate command arguments without a space.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <p><strong>Scenario:</strong> A file-info tool runs <code>file</code> on the path you provide. Literal spaces are filtered, but bash offers several space substitutes. Chain a command using <code>${IFS}</code>, <code>%09</code> (tab), or <code>{cmd,arg}</code> brace expansion to read the flag without any space character.</p>
                    </div>

                    <div class="code-block">Command: file <?php echo htmlspecialchars($_GET['filename'] ?? '[FILENAME]'); ?></div>

                    <?php if ($result_error !== null): ?>
                        <div class="error"><?php echo htmlspecialchars($result_error); ?></div>
                    <?php endif; ?>
                    <?php if ($result_output !== null): ?>
                        <div class="result"><pre><?php echo htmlspecialchars($result_output); ?></pre></div>
                    <?php endif; ?>

                    <form method="get">
                        <div class="form-group">
                            <label for="filename">Filename:</label>
                            <input type="text" id="filename" name="filename"
                                   value="<?php echo htmlspecialchars($_GET['filename'] ?? ''); ?>"
                                   placeholder="Enter filename (e.g., /etc/passwd)"
                                   oninput="updateCommand(this.value)">
                        </div>
                        <button type="submit" class="btn">Get File Info</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section($hints) ?>

        <?= render_inline_flag_form(3, $_flag_result) ?>

        <div class="navigation">
            <a href="level2.php">Previous Level</a>
            <a href="index.php">Home</a>
            <a href="level4.php">Next Level</a>
            <a href="submit.php?level=3">Submit Flag</a>
        </div>
    </div>

    <script>
    function updateCommand(val) {
        document.querySelector('.code-block').textContent =
            'Command: file ' + (val || '[FILENAME]');
    }
    </script>
</body>
</html>
