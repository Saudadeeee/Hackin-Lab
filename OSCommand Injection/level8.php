<?php
require_once __DIR__ . '/helpers.php';

$output_html = '';

if (isset($_GET['ports'])) {
    require_once 'flag_system.php';
    get_level_flag(8);

    $ports = $_GET['ports'];

    $waf_patterns = [
        '/[\;\&\|`\$\(\)]/i',
        '/\b(cat|ls|whoami|id|passwd|shadow|flag)\b/i',
        '/\b(wget|curl|nc|netcat|bash|sh)\b/i',
        '/\s+/i',
        '/\.\.\//i',
    ];

    $blocked         = false;
    $matched_pattern = '';

    foreach ($waf_patterns as $pattern) {
        if (preg_match($pattern, $ports)) {
            $blocked         = true;
            $matched_pattern = $pattern;
            break;
        }
    }

    ob_start();
    if ($blocked) {
        echo '<div class="error">WAF ALERT: Malicious pattern detected &mdash; ' . htmlspecialchars($matched_pattern) . '</div>';
        echo '<div class="error">Request blocked by Web Application Firewall</div>';
    } else {
        $command = "nmap -sS -p " . $ports . " localhost";
        $raw     = shell_exec($command . " 2>&1");

        if ($raw) {
            echo '<pre>' . htmlspecialchars($raw) . '</pre>';
        } else {
            echo '<div class="message success">Scan completed &mdash; No open ports found</div>';
        }
    }
    $output_html = ob_get_clean();
}

$hints = get_level_hints(8);
$_flag_result = handle_inline_flag_submit(8);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 8 - WAF Bypass &amp; Context Breaking</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 8 - WAF Bypass &amp; Context Breaking</h1>
            <p><strong>Objective:</strong> Bypass a Web Application Firewall using context breaking and advanced techniques</p>
            <a href="index.php" class="back-btn">&larr; Back to Levels</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-variable">$ports</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'ports'</span>];

<span class="php-variable">$waf_patterns</span> = [
    <span class="php-string">'/[\;\&amp;\|`\$\(\)]/i'</span>,          <span class="php-comment">// shell metacharacters</span>
    <span class="php-string">'/\b(cat|ls|whoami|id|passwd|shadow|flag)\b/i'</span>,
    <span class="php-string">'/\b(wget|curl|nc|netcat|bash|sh)\b/i'</span>,
    <span class="php-string">'/\s+/i'</span>,                          <span class="php-comment">// all whitespace</span>
    <span class="php-string">'/\.\.\//i'</span>,                       <span class="php-comment">// path traversal</span>
];

<span class="php-keyword">foreach</span> (<span class="php-variable">$waf_patterns</span> <span class="php-keyword">as</span> <span class="php-variable">$pattern</span>) {
    <span class="php-keyword">if</span> (preg_match(<span class="php-variable">$pattern</span>, <span class="php-variable">$ports</span>)) {
        <span class="php-keyword">echo</span> <span class="php-string">'WAF ALERT: blocked'</span>; <span class="php-keyword">exit</span>;
    }
}

<span class="php-comment">// Passes WAF — still concatenated unsafely</span>
<span class="vuln-line"><span class="php-variable">$command</span> = <span class="php-string">"nmap -sS -p "</span> . <span class="php-variable">$ports</span> . <span class="php-string">" localhost"</span>;</span>
<span class="php-variable">$output</span>  = shell_exec(<span class="php-variable">$command</span> . <span class="php-string">" 2&gt;&amp;1"</span>);</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; Five WAF regex patterns block metacharacters, dangerous commands, network tools, whitespace, and path traversal — but the construction of <code>$command</code> still concatenates <code>$ports</code> directly. Find a payload that satisfies all five patterns simultaneously while still injecting a second shell command.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <p><strong>Tool:</strong> Security Scanner — wraps <code>nmap -sS -p &lt;input&gt; localhost</code> behind a multi-rule WAF. Blocked patterns: shell metacharacters, dangerous commands, network tools, whitespace, and <code>../</code>.</p>
                        <p>Craft a single input that passes every WAF rule yet injects a second command. Newline injection (<code>%0a</code>) and tab-as-whitespace (<code>%09</code>) are common starting points.</p>
                    </div>

                    <?php if ($output_html !== ''): ?>
                        <div class="result"><?= $output_html ?></div>
                    <?php endif; ?>

                    <form method="get">
                        <div class="form-group">
                            <label for="ports">Port Range:</label>
                            <input type="text" id="ports" name="ports"
                                   value="<?= htmlspecialchars($_GET['ports'] ?? '') ?>"
                                   placeholder="e.g., 80,443,22">
                        </div>
                        <button type="submit" class="btn">Start Scan</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section($hints) ?>

        <?= render_inline_flag_form(8, $_flag_result) ?>

        <div class="navigation">
            <a href="level7.php">Previous Level</a>
            <a href="index.php">Home</a>
            <a href="level9.php">Next Level</a>
            <a href="submit.php?level=8">Submit Flag</a>
        </div>
    </div>
</body>
</html>
