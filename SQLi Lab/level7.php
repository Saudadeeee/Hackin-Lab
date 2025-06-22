<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 7 - Second Order SQLi</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔄 Level 7 - Second Order Injection</h1>
            <p><strong>Attack Type:</strong> Execute stored payloads in a second request, exploiting data flow between operations</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">
                1. SELECT mvalue FROM meta WHERE mkey = '<?php echo htmlspecialchars($_GET['key'] ?? 'NULL'); ?>'<br>
                2. SELECT flag FROM levels WHERE id = [retrieved_value]
            </div>
            
            <?php
            if (isset($_GET['key'])) {
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $key = $_GET['key'];
                $res = $mysqli->query("SELECT mvalue FROM meta WHERE mkey = '$key'") or die($mysqli->error);
                $row = $res->fetch_assoc();
                if (!$row) {
                    echo '<div class="error">Key not found. Did you store it in <a href="level7_set.php">Level 7 Setup</a>?</div>';
                } else {
                    $v = $row['mvalue'];
                    echo '<p><strong>Retrieved value:</strong> ' . htmlspecialchars($v) . '</p>';
                    $sql2 = "SELECT flag FROM levels WHERE id = $v";
                    $res2 = $mysqli->query($sql2) or die($mysqli->error);
                    $row2 = $res2->fetch_assoc();
                    if ($row2) {
                        echo '<p><strong>Flag:</strong> ' . htmlspecialchars($row2['flag']) . '</p>';
                    } else {
                        echo '<p>Flag not found</p>';
                    }
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Execute Stored Payload:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="key">Key to Retrieve:</label>
                    <input type="text" id="key" name="key" value="<?php echo htmlspecialchars($_GET['key'] ?? ''); ?>" placeholder="Enter key to retrieve...">
                </div>
                <button type="submit" class="btn">🚀 Execute Query</button>
            </form>
            
            <h3>📋 Quick Examples:</h3>
            <div style="display: flex; gap: 10px; flex-wrap: wrap; margin: 20px 0;">
                <a href="?key=test" class="btn">Stored: key=test</a>
                <a href="?key=flag7" class="btn">Target: key=flag7</a>
                <a href="level7_set.php?key=flag7&value=7" class="btn">Store Level 7 ID</a>
            </div>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding Second Order Injection</h4>
                    <p>Second order injection occurs when malicious input is stored in the database and later used in another query without proper sanitization.</p>
                    <p>This level has two steps: first store data, then retrieve and use it.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: The Two-Step Process</h4>
                    <p>Step 1: Use level7_set.php to store a key-value pair in the database</p>
                    <p>Step 2: Use level7.php to retrieve the stored value and use it in a query</p>
                    <p>The vulnerability is in the second step where the stored value is used directly.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Storing the Target ID</h4>
                    <p>We need to store the level ID (7) so that when retrieved, it will fetch the flag for level 7.</p>
                    <p>Go to level7_set.php and store: key="flag7" with value="7"</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Retrieving the Flag</h4>
                    <p>After storing the key-value pair, come back to level7.php and retrieve it.</p>
                    <p>Use key="flag7" to retrieve the stored value "7"</p>
                    <p>This will execute: SELECT flag FROM levels WHERE id = 7</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Solution - Complete Steps</h4>
                    <p>Step 1: Go to <a href="level7_set.php?key=flag7&value=7">level7_set.php?key=flag7&value=7</a></p>
                    <p>Step 2: Come back to <a href="?key=flag7">level7.php?key=flag7</a></p>
                    <p>This will store level ID 7 and then retrieve the flag for level 7.</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level6.php">⬅️ Previous Level</a>
            <a href="level8.php">➡️ Next Level</a>
            <a href="submit.php?level=7">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

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