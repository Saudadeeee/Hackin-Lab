<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 8 - XPATH Injection</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🗂️ Level 8 - XPATH Injection</h1>
            <p><strong>Attack Type:</strong> Exploit XPATH functions to extract data through XML processing errors</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">SELECT * FROM users WHERE username = '<?php echo htmlspecialchars($_GET['user'] ?? 'NULL'); ?>' AND id = extractvalue(1, '<?php echo htmlspecialchars($_GET['pass'] ?? 'NULL'); ?>')</div>
            
            <?php
            if (isset($_GET['user']) && isset($_GET['pass'])) {
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $user = $_GET['user'];
                $pass = $_GET['pass'];

                $sql = "SELECT * FROM users WHERE username = '$user' AND id = extractvalue(1, '$pass')";
                $result = $mysqli->query($sql);

                if (!$result) {
                    echo '<div class="error">Error: '.$mysqli->error.'</div>';
                } else {
                    if ($result->num_rows > 0) {
                        echo '✅ Login successful';
                    } else {
                        echo '❌ Login failed';
                    }
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Own Payload:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="user">Username:</label>
                    <input type="text" id="user" name="user" value="<?php echo htmlspecialchars($_GET['user'] ?? ''); ?>" placeholder="Enter username..." oninput="updateQuery()">
                </div>
                <div class="form-group">
                    <label for="pass">Password (XPATH):</label>
                    <input type="text" id="pass" name="pass" value="<?php echo htmlspecialchars($_GET['pass'] ?? ''); ?>" placeholder="Enter XPATH payload..." oninput="updateQuery()">
                </div>
                <button type="submit" class="btn">🚀 Execute Query</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding EXTRACTVALUE</h4>
                    <p>The EXTRACTVALUE() function extracts values from XML using XPATH expressions.</p>
                    <p>Try: <code>user=admin</code> and <code>pass=test</code> to see normal behavior.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Breaking XPATH</h4>
                    <p>Invalid XPATH expressions cause errors that reveal data.</p>
                    <p>Try: <code>user=admin</code> and <code>pass=/flag</code></p>
                    <p>The slash makes it an invalid XPATH expression.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Using CONCAT in XPATH</h4>
                    <p>Use concat() to combine tilde characters with SQL queries:</p>
                    <p>Try: <code>user=admin</code> and <code>pass=concat(0x7e, 'TEST', 0x7e)</code></p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Subquery in XPATH</h4>
                    <p>Now inject a SQL subquery inside the XPATH expression:</p>
                    <p>Try: <code>user=admin</code> and <code>pass=concat(0x7e, (SELECT database()), 0x7e)</code></p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload</h4>
                    <p>Extract the flag from the levels table:</p>
                    <p><code>user=admin</code> and <code>pass=concat(0x7e, (SELECT flag FROM levels WHERE id=8), 0x7e)</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level7.php">⬅️ Previous Level</a>
            <a href="level9.php">➡️ Next Level</a>
            <a href="submit.php?level=8">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateQuery() {
        const user = document.getElementById('user').value;
        const pass = document.getElementById('pass').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = "SELECT * FROM users WHERE username = '" + (user || 'NULL') + "' AND id = extractvalue(1, '" + (pass || 'NULL') + "')";
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
</body>
</html>
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
        to { opacity: 1; transform: translateY(0); }
    }
    </style>
</body>
</html>
