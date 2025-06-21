<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 7 Setup - Second Order SQLi</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔄 Level 7 Setup - Second Order Injection</h1>
            <p><strong>Step 1:</strong> Store a payload in the database that will be executed in the next step</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">INSERT INTO meta (mkey, mvalue) VALUES ('<?php echo htmlspecialchars($_GET['key'] ?? 'NULL'); ?>', '<?php echo htmlspecialchars($_GET['value'] ?? 'NULL'); ?>') ON DUPLICATE KEY UPDATE mvalue = '<?php echo htmlspecialchars($_GET['value'] ?? 'NULL'); ?>'</div>
            
            <?php
            if (isset($_GET['key']) && isset($_GET['value'])) {
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $key = $_GET['key'];
                $value = $_GET['value'];
                $sql = "INSERT INTO meta (mkey, mvalue) VALUES ('$key', '$value') ON DUPLICATE KEY UPDATE mvalue = '$value'";
                if ($mysqli->query($sql)) {
                    echo '✅ Data stored successfully. Now go to <a href="level7.php?key=' . urlencode($key) . '">Level 7</a> to execute the second query.';
                } else {
                    echo '<div class="error">Error: '.$mysqli->error.'</div>';
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Store Your Payload:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="key">Key:</label>
                    <input type="text" id="key" name="key" value="<?php echo htmlspecialchars($_GET['key'] ?? ''); ?>" placeholder="Enter key name..." oninput="updateQuery()">
                </div>
                <div class="form-group">
                    <label for="value">Value:</label>
                    <input type="text" id="value" name="value" value="<?php echo htmlspecialchars($_GET['value'] ?? ''); ?>" placeholder="Enter your payload value..." oninput="updateQuery()">
                </div>
                <button type="submit" class="btn">💾 Store Data</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Second Order Injection Setup</h4>
                    <p>This is the first step of a second order injection attack.</p>
                    <p>We store malicious data in the database that will be used unsafely in a later query.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Understanding the Meta Table</h4>
                    <p>The meta table stores key-value pairs that can be retrieved later.</p>
                    <p>The stored value will be used directly in a SQL query without sanitization.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Targeting Level 7</h4>
                    <p>We want to retrieve the flag for level 7, so we need to store the level ID.</p>
                    <p>Try storing: key="flag7" and value="7"</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: The Connection</h4>
                    <p>After storing the data here, go to level7.php and retrieve it using the same key.</p>
                    <p>The retrieved value will be inserted into: SELECT flag FROM levels WHERE id = [value]</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload - Store the Level ID</h4>
                    <p>Use these values to store the level 7 ID:</p>
                    <p>Key: <code>flag7</code></p>
                    <p>Value: <code>7</code></p>
                    <p>Then go to level7.php?key=flag7 to retrieve the flag.</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level6.php">⬅️ Previous Level</a>
            <a href="level7.php">➡️ Execute Level 7</a>
            <a href="submit.php?level=7">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateQuery() {
        const key = document.getElementById('key').value;
        const value = document.getElementById('value').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = "INSERT INTO meta (mkey, mvalue) VALUES ('" + (key || 'NULL') + "', '" + (value || 'NULL') + "') ON DUPLICATE KEY UPDATE mvalue = '" + (value || 'NULL') + "'";
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